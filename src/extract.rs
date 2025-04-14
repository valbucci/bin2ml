use crate::afij::AFIJFunctionInfo;
use crate::agcj::AGCJFunctionCallGraph;

use std::io;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Error;
use anyhow::Result;
use r2pipe::R2Pipe;
use r2pipe::R2PipeSpawnOptions;

use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;
use serde_json;

use serde_json::{json, Deserializer, Value};
use std::collections::HashMap;
use std::env;

use glob::glob;
use regex::Regex;
use std::fs;
use std::fs::File;
use std::string::String;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(PartialEq, Debug)]
pub enum PathType {
    Pattern,
    File,
    Dir,
    Unk,
}
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ExtractionJobType {
    BinInfo, // Extract high level information from the binary (r2 ij)
    RegisterBehaviour,
    FunctionXrefs,
    CFG,
    CallGraphs,
    FuncInfo,
    FunctionVariables,
    Decompilation,
    PCodeFunc,
    PCodeBB,
    LocalVariableXrefs,
    GlobalStrings,
    FunctionBytes,
    FunctionZignatures,
}

#[derive(Debug)]
pub struct FileToBeProcessed {
    pub file_path: PathBuf,
    pub output_path: PathBuf,
    pub job_types: Vec<ExtractionJobType>,
    pub r2p_config: R2PipeConfig,
    pub with_annotations: bool,
}

#[derive(Debug)]
pub struct ExtractionJob {
    pub input_path: PathBuf,
    pub input_path_type: PathType,
    pub job_types: Vec<(ExtractionJobType, String)>,
    pub files_to_be_processed: Vec<FileToBeProcessed>,
    pub output_path: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct R2PipeConfig {
    pub debug: bool,
    pub extended_analysis: bool,
    pub use_curl_pdb: bool,
}

impl std::fmt::Display for ExtractionJob {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "bin_path: {:?} p_type: {:?} jobs: {:?}",
            self.input_path, self.input_path_type, self.job_types
        )
    }
}

// Structs related to AFLJ r2 command
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AFLJFuncDetails {
    pub offset: u64,
    pub name: String,
    pub size: u64,
    #[serde(rename = "is-pure")]
    pub is_pure: String,
    pub realsz: u64,
    pub noreturn: bool,
    pub stackframe: u64,
    pub calltype: String,
    pub cost: u64,
    pub cc: u64,
    pub bits: u64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub nbbs: u64,
    #[serde(rename = "is-lineal")]
    pub is_lineal: bool,
    pub ninstrs: u64,
    pub edges: u64,
    pub ebbs: u64,
    pub signature: String,
    pub minbound: i64,
    pub maxbound: u64,
    #[serde(default)]
    pub callrefs: Vec<Callref>,
    #[serde(default)]
    pub datarefs: Vec<DataRef>,
    pub indegree: Option<u64>,
    pub outdegree: Option<u64>,
    pub nlocals: Option<u64>,
    pub nargs: Option<u64>,
    pub bpvars: Option<Vec<Bpvar>>,
    pub spvars: Option<Vec<Value>>,
    pub regvars: Option<Vec<Regvar>>,
    pub difftype: Option<String>,
    #[serde(default)]
    pub codexrefs: Option<Vec<Codexref>>,
    #[serde(default)]
    pub dataxrefs: Option<Vec<u64>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", transparent)]
pub struct DataRef {
    #[serde(deserialize_with = "deserialize_string_from_number")]
    value: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Callref {
    pub addr: u64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bpvar {
    pub name: String,
    pub kind: String,
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "ref")]
    pub ref_field: Ref,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ref {
    pub base: String,
    pub offset: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Regvar {
    pub name: String,
    pub kind: String,
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "ref")]
    pub ref_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Codexref {
    pub addr: u64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: u64,
}

// Structs related to AEAFJ
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AEAFJRegisterBehaviour {
    #[serde(rename = "A")]
    pub a: Vec<String>,
    #[serde(rename = "I")]
    pub i: Vec<String>,
    #[serde(rename = "R")]
    pub r: Vec<String>,
    #[serde(rename = "W")]
    pub w: Vec<String>,
    #[serde(rename = "V")]
    pub v: Vec<String>,
    #[serde(rename = "N")]
    #[serde(default)]
    pub n: Vec<String>,
    #[serde(rename = "@R")]
    #[serde(default)]
    pub r2: Vec<u64>,
    #[serde(rename = "@W")]
    #[serde(default)]
    pub w2: Vec<u64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// Created using the axffj command
pub struct FunctionXrefDetails {
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: i64,
    #[serde(rename = "ref")]
    pub ref_field: i128,
    pub name: String,
}

impl std::fmt::Display for AFLJFuncDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "name: {}", self.name)
    }
}

impl From<(String, String, Vec<ExtractionJobType>, R2PipeConfig, bool)> for FileToBeProcessed {
    fn from(
        orig: (String, String, Vec<ExtractionJobType>, R2PipeConfig, bool),
    ) -> FileToBeProcessed {
        FileToBeProcessed {
            file_path: PathBuf::from(orig.0),
            output_path: PathBuf::from(orig.1),
            job_types: orig.2,
            r2p_config: orig.3,
            with_annotations: orig.4,
        }
    }
}

// Structs for pdgj - Ghidra Decomp JSON output
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecompJSON {
    pub code: String,
    pub annotations: Vec<Annotation>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Annotation {
    pub start: i64,
    pub end: i64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub syntax_highlight: Option<String>,
    pub name: Option<String>,
    pub offset: Option<i64>,
}

// Structs  for pdgsd - Ghidra PCode JSON output
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJSON {
    pub pcode: Vec<String>,
    pub asm: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJSONWithFuncName {
    pub function_name: String,
    pub pcode: PCodeJSON,
}

// Structs for pdgsd + basic block connectivity - Ghidra PCode JSON Output + afbj
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJsonWithBB {
    pub block_start_adr: u64,
    pub pcode: Vec<String>,
    pub asm: Option<Vec<String>>,
    pub bb_info: BasicBlockMetadataEntry,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJsonWithBBAndFuncName {
    pub function_name: String,
    pub pcode_blocks: Vec<PCodeJsonWithBB>,
}

// Structs for afbj - Basic Block JSON output
pub type BasicBlockInfo = Vec<BasicBlockMetadataEntry>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasicBlockMetadataEntry {
    pub addr: u64,
    pub size: u64,
    pub jump: Option<u64>,
    pub fail: Option<u64>,
    pub opaddr: u64,
    pub inputs: u64,
    pub outputs: u64,
    pub ninstr: u64,
    pub instrs: Vec<u64>,
    pub traced: bool,
}

// Structs for axvj - Local Variable Xref JSON output
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalVariableXrefs {
    pub reads: Vec<Reads>,
    pub writes: Vec<Writes>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reads {
    pub name: String,
    pub addrs: Vec<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Writes {
    pub name: String,
    pub addrs: Vec<i64>,
}

// Structs for afvj - Function Arguments, Registers, and Variables JSON output
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AFVJFuncDetails {
    pub reg: Vec<Regvar>,
    pub sp: Vec<Value>,
    pub bp: Vec<Bpvar>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StringEntry {
    pub vaddr: i64,
    pub paddr: i64,
    pub ordinal: i64,
    pub size: i64,
    pub length: i64,
    pub section: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuncBytes {
    pub bytes: Vec<u8>,
}

// Structs for zj - Function signatures (called "zignatures" in r2)
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEntry {
    pub cc: u64,
    pub nbbs: u64,
    pub edges: u64,
    pub ebbs: u64,
    pub bbsum: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VarEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub kind: char,
    pub delta: i64,
    pub isarg: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashEntry {
    pub bbhash: String, // hexadecimal
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionZignature {
    pub name: String,
    pub bytes: String, // hexadecimal function bytes
    pub mask: String,  // hexadecimal
    pub graph: GraphEntry,
    pub addr: i64,
    pub next: Option<String>,
    pub types: String,
    pub refs: Vec<String>,
    pub xrefs: Vec<String>,
    pub collisions: Vec<String>, // colliding function names
    pub vars: Vec<VarEntry>,
    pub hash: HashEntry,
}

// Structs for ij - Information about the binary file
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecksumsEntry {
    // Output of itj
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreEntry {
    #[serde(rename = "type")]
    pub type_field: String,
    pub file: String,
    pub fd: i32,
    pub size: u64,
    pub humansz: String,
    pub iorw: bool,
    pub mode: String,
    pub block: u64,
    pub format: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinEntry {
    pub arch: String,
    pub baddr: Option<u64>,
    pub binsz: u64,
    pub bintype: String,
    pub bits: u16,
    pub canary: bool,
    pub injprot: bool,
    pub retguard: Option<bool>,
    pub class: String,
    #[serde(rename = "cmp.csum")]
    pub cmp_csum: Option<String>,
    pub compiled: String,
    pub compiler: String,
    pub crypto: bool,
    pub dbg_file: String,
    pub endian: String,
    pub havecode: bool,
    #[serde(rename = "hdr.csum")]
    pub hdr_csum: Option<String>,
    pub guid: String,
    pub intrp: String,
    pub laddr: u64,
    pub lang: Option<String>,
    pub linenum: bool,
    pub lsyms: bool,
    pub machine: String,
    pub nx: bool,
    pub os: String,
    pub overlay: Option<bool>,
    pub cc: String,
    pub pic: bool,
    pub relocs: bool,
    pub rpath: String,
    pub signed: Option<bool>,
    pub sanitize: bool,
    #[serde(rename = "static")]
    pub static_field: bool,
    pub stripped: bool,
    pub subsys: String,
    pub va: bool,
    pub checksums: HashMap<String, String>, // Always empty.
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub core: CoreEntry,
    pub bin: Option<BinEntry>, // Sometimes not provided within ij.
    pub checksums: Option<ChecksumsEntry>, // Populated manually with itj.
}

impl ExtractionJob {
    pub fn new(
        input_path: &PathBuf,
        output_path: &PathBuf,
        modes: &Vec<String>,
        debug: &bool,
        extended_analysis: &bool,
        use_curl_pdb: &bool,
        with_annotations: &bool,
    ) -> Result<ExtractionJob, Error> {
        fn get_path_type(bin_path: &PathBuf) -> PathType {
            // Handle pattern first since it would raise NotFound error
            let path_str = bin_path.to_string_lossy();
            if path_str.contains('*') || path_str.contains('?') || path_str.contains('[') {
                return PathType::Pattern;
            }

            let fpath_md = fs::metadata(bin_path).unwrap();
            if fpath_md.is_file() {
                PathType::File
            } else if fpath_md.is_dir() {
                PathType::Dir
            } else {
                PathType::Unk
            }
        }

        // This function is used to validate modes and convert them to job types
        fn extraction_job_matcher(mode: &str) -> Result<ExtractionJobType, Error> {
            match mode {
                "bininfo" => Ok(ExtractionJobType::BinInfo),
                "finfo" => Ok(ExtractionJobType::FuncInfo),
                "fvars" => Ok(ExtractionJobType::FunctionVariables),
                "reg" => Ok(ExtractionJobType::RegisterBehaviour),
                "cfg" => Ok(ExtractionJobType::CFG),
                "func-xrefs" => Ok(ExtractionJobType::FunctionXrefs),
                "cg" => Ok(ExtractionJobType::CallGraphs),
                "decomp" => Ok(ExtractionJobType::Decompilation),
                "pcode-func" => Ok(ExtractionJobType::PCodeFunc),
                "pcode-bb" => Ok(ExtractionJobType::PCodeBB),
                "localvar-xrefs" => Ok(ExtractionJobType::LocalVariableXrefs),
                "strings" => Ok(ExtractionJobType::GlobalStrings),
                "bytes" => Ok(ExtractionJobType::FunctionBytes),
                "zigs" => Ok(ExtractionJobType::FunctionZignatures),
                _ => bail!("Incorrect command type - got {}", mode),
            }
        }

        let mut job_types = vec![];
        let mut extraction_job_types = vec![];

        for mode in modes {
            let job_type = extraction_job_matcher(mode)?;
            job_types.push((job_type, mode.clone()));
            extraction_job_types.push(job_type); // Store just the job type

            if job_type != ExtractionJobType::Decompilation && *with_annotations {
                warn!(
                    "Annotations are only supported for decompilation extraction (mode: {})",
                    mode
                );
            }
        }

        let r2_handle_config = R2PipeConfig {
            debug: *debug,
            extended_analysis: *extended_analysis,
            use_curl_pdb: *use_curl_pdb,
        };

        let p_type = get_path_type(input_path);

        if p_type == PathType::File {
            // For a single file, create one FileToBeProcessed object
            // but track all the job types
            let file = FileToBeProcessed {
                file_path: input_path.to_owned(),
                output_path: output_path.to_owned(),
                job_types: extraction_job_types, // Use the vector of just ExtractionJobType
                r2p_config: r2_handle_config,
                with_annotations: *with_annotations,
            };

            Ok(ExtractionJob {
                input_path: input_path.to_owned(),
                input_path_type: p_type,
                job_types,
                files_to_be_processed: vec![file],
                output_path: output_path.to_owned(),
            })
        } else if p_type == PathType::Dir {
            // For a directory, get all file paths
            let files = ExtractionJob::get_file_paths_dir(input_path);

            // Create FileToBeProcessed objects for each file with all job types
            let files_to_be_processed = files
                .into_iter()
                .map(|f| FileToBeProcessed {
                    file_path: PathBuf::from(f),
                    output_path: output_path.to_owned(),
                    job_types: extraction_job_types.clone(),
                    r2p_config: r2_handle_config,
                    with_annotations: *with_annotations,
                })
                .collect();

            Ok(ExtractionJob {
                input_path: input_path.to_owned(),
                input_path_type: p_type,
                job_types,
                files_to_be_processed,
                output_path: output_path.to_owned(),
            })
        } else if p_type == PathType::Pattern {
            // For a match pattern get the list of matching file paths
            let pattern = input_path.to_string_lossy();
            let files = ExtractionJob::get_file_paths_pattern(&pattern);

            // Create FileToBeProcessed objects for each file with all job types
            let files_to_be_processed = files
                .into_iter()
                .map(|f| FileToBeProcessed {
                    file_path: PathBuf::from(f),
                    output_path: output_path.to_owned(),
                    job_types: extraction_job_types.clone(),
                    r2p_config: r2_handle_config,
                    with_annotations: *with_annotations,
                })
                .collect();

            Ok(ExtractionJob {
                input_path: input_path.to_owned(),
                input_path_type: PathType::Dir, // For using parallel processing
                job_types,
                files_to_be_processed,
                output_path: output_path.to_owned(),
            })
        } else {
            bail!("Failed to create ExtractionJob")
        }
    }

    fn get_file_paths_dir(input_path: &PathBuf) -> Vec<String> {
        let mut str_vec: Vec<String> = Vec::new();
        for file in WalkDir::new(input_path)
            .into_iter()
            .filter_map(|file| file.ok())
        {
            if file.metadata().unwrap().is_file()
                && !file.file_name().to_string_lossy().ends_with(".json")
            {
                let f_string =
                    String::from(<&std::path::Path>::clone(&file.path()).to_str().unwrap());
                str_vec.push(f_string.clone());
            }
        }
        str_vec
    }

    fn get_file_paths_pattern(pattern: &str) -> Vec<String> {
        let mut paths = Vec::new();
        // glob returns an iterator over Result<PathBuf, GlobError>
        for entry in glob(pattern)
            .expect("Failed to read glob pattern")
            .flatten()
        {
            if !entry.to_string_lossy().ends_with(".json") {
                paths.push(entry.to_string_lossy().to_string());
            }
        }

        paths
    }
}

impl FileToBeProcessed {
    pub fn get_output_filename(&self, job_type_suffix: &str) -> String {
        let mut fp_filename = self
            .file_path
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();

        fp_filename = if job_type_suffix == "bytes" || job_type_suffix == "bytes.__part" {
            fp_filename + "_" + job_type_suffix
        } else if self.with_annotations {
            fp_filename + "_" + job_type_suffix + "_annotations" + ".json"
        } else {
            fp_filename + "_" + job_type_suffix + ".json"
        };
        fp_filename
    }

    pub fn get_output_filepath(&self, job_type_suffix: &str) -> PathBuf {
        let fp_filename = self.get_output_filename(job_type_suffix);

        let mut output_filepath = PathBuf::new();
        output_filepath.push(self.output_path.clone());
        output_filepath.push(fp_filename);

        output_filepath.clone()
    }

    pub fn process_mode(&self, r2p: &mut R2Pipe, job_type: &ExtractionJobType) -> Result<()> {
        let job_type_suffix = self.get_job_type_suffix(job_type);
        // Use temporary name to keep track of incomplete extraction
        let tmp_job_type_suffix = format!("{}.__part", job_type_suffix).to_string();
        let tmp_output_path = self.get_output_filepath(&tmp_job_type_suffix);

        match job_type {
            ExtractionJobType::BinInfo => self.extract_binary_info(r2p, tmp_job_type_suffix),
            ExtractionJobType::RegisterBehaviour => {
                self.extract_register_behaviour(r2p, tmp_job_type_suffix)
            }
            ExtractionJobType::FunctionXrefs => {
                self.extract_function_xrefs(r2p, tmp_job_type_suffix)
            }
            ExtractionJobType::CFG => self.extract_func_cfgs(r2p, tmp_job_type_suffix),
            ExtractionJobType::CallGraphs => {
                self.extract_function_call_graphs(r2p, tmp_job_type_suffix)
            }
            ExtractionJobType::FuncInfo => self.extract_function_info(r2p, tmp_job_type_suffix),
            ExtractionJobType::FunctionVariables => {
                self.extract_function_variables(r2p, tmp_job_type_suffix)
            }
            ExtractionJobType::Decompilation => {
                self.extract_decompilation(r2p, tmp_job_type_suffix)
            }
            ExtractionJobType::PCodeFunc => self.extract_pcode_function(r2p, tmp_job_type_suffix),
            ExtractionJobType::PCodeBB => self.extract_pcode_basic_block(r2p, tmp_job_type_suffix),
            ExtractionJobType::LocalVariableXrefs => {
                self.extract_local_variable_xrefs(r2p, tmp_job_type_suffix)
            }
            ExtractionJobType::GlobalStrings => {
                self.extract_global_strings(r2p, tmp_job_type_suffix)
            }
            ExtractionJobType::FunctionZignatures => {
                self.extract_function_zignatures(r2p, tmp_job_type_suffix)
            }
            ExtractionJobType::FunctionBytes => {
                self.extract_function_bytes(r2p, tmp_job_type_suffix)
            }
        }?;

        // Apply final output file name when extraction is done
        let output_path = self.get_output_filepath(&job_type_suffix);
        std::fs::rename(&tmp_output_path, &output_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to rename temporary path {:?}: {}",
                tmp_output_path,
                e
            )
        })?;
        Ok(())
    }

    pub fn process_all_modes(&self) {
        info!(
            "Starting extraction for {} job types on {:?}",
            self.job_types.len(),
            self.file_path
        );

        // Skip processing if no job types
        if self.job_types.is_empty() {
            info!("No job types to process for {:?}", self.file_path);
            return;
        }

        // Set up a single r2pipe instance
        let mut maybe_r2p: Option<R2Pipe> = None;

        // Process each job type with the same r2pipe instance
        for job_type in &self.job_types {
            info!("Processing job type: {:?}", job_type);

            // Check if the extracted data file already exists
            let job_type_suffix = self.get_job_type_suffix(job_type);
            let output_path = self.get_output_filepath(&job_type_suffix);
            if Path::new(&output_path).exists() {
                warn!(
                    "Skipping {:?} job for {:?}: already processed at {:?}.",
                    job_type_suffix, self.file_path, output_path
                );
                continue;
            }

            // Lazily initialize r2p if not already done.
            let r2p = maybe_r2p.get_or_insert_with(|| {
                let mut pipe = self.setup_r2_pipe();
                self.analyse_r2_pipe(&mut pipe);
                pipe
            });

            match self.process_mode(r2p, job_type) {
                Ok(_) => debug!(
                    "Finished {:?} extraction job for {:?}: processed at {:?}.",
                    job_type_suffix, self.file_path, output_path
                ),
                Err(e) => error!(
                    "Aborted {:?} extraction job for {:?} due to error: {:?}.",
                    job_type_suffix, self.file_path, e
                ),
            }
        }

        // Close the r2pipe instance once after processing all job types
        if let Some(mut r2p) = maybe_r2p {
            r2p.close();
            info!("r2p closed after processing all job types");
        }
    }

    pub fn get_job_type_suffix(&self, job_type: &ExtractionJobType) -> String {
        match job_type {
            ExtractionJobType::BinInfo => "bininfo",
            ExtractionJobType::RegisterBehaviour => "reg",
            ExtractionJobType::FunctionXrefs => "func-xrefs",
            ExtractionJobType::CFG => "cfg",
            ExtractionJobType::CallGraphs => "cg",
            ExtractionJobType::FuncInfo => "finfo",
            ExtractionJobType::FunctionVariables => "fvars",
            ExtractionJobType::Decompilation => "decomp",
            ExtractionJobType::PCodeFunc => "pcode-func",
            ExtractionJobType::PCodeBB => "pcode-bb",
            ExtractionJobType::LocalVariableXrefs => "localvar-xrefs",
            ExtractionJobType::GlobalStrings => "strings",
            ExtractionJobType::FunctionZignatures => "zigs",
            ExtractionJobType::FunctionBytes => "bytes",
        }
        .to_string()
    }

    pub fn extract_binary_info(&self, r2p: &mut R2Pipe, job_type_suffix: String) -> Result<()> {
        info!("Starting binary information extraction");
        let bininfo_json = r2p
            .cmd("ij")
            .with_context(|| "ij command failed to execute")?;
        let mut bininfo: BinaryInfo = serde_json::from_str(&bininfo_json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", bininfo_json))?;

        let checksums_json = r2p
            .cmd("itj")
            .with_context(|| format!("Command itj failed in {:?}.", self.file_path))?;
        let checksums: ChecksumsEntry = serde_json::from_str(&checksums_json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", checksums_json))?;

        bininfo.checksums = Some(checksums);
        info!("Binary information extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(bininfo), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_register_behaviour(
        &self,
        r2p: &mut R2Pipe,
        job_type_suffix: String,
    ) -> Result<()> {
        let function_details = self.get_function_name_list(r2p)?;
        let mut register_behaviour_vec: HashMap<String, AEAFJRegisterBehaviour> = HashMap::new();
        info!("Executing aeafj for each function");
        for function in function_details.iter() {
            let seek_cmd = format!("s @ {}", &function.name);
            r2p.cmd(seek_cmd.as_str()).with_context(|| {
                format!("Command {:?} failed in {:?}.", seek_cmd, self.file_path)
            })?;
            let json = r2p.cmd("aeafj").with_context(|| {
                format!(
                    "Command aeafj failed in {:?} at function {:?}.",
                    self.file_path, function.name
                )
            })?;
            let json_obj: AEAFJRegisterBehaviour = serde_json::from_str(&json)
                .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
            register_behaviour_vec.insert(function.name.clone(), json_obj);
        }
        info!("All functions processed");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(register_behaviour_vec), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_function_call_graphs(
        &self,
        r2p: &mut R2Pipe,
        job_type_suffix: String,
    ) -> Result<()> {
        info!("Starting function call graph extraction");
        let json = r2p
            .cmd("agCj")
            .with_context(|| format!("agCj command failed to execute on {:?}", self.file_path))?;
        let function_call_graphs: Vec<AGCJFunctionCallGraph> = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        info!("Function call graph extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_call_graphs), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_function_info(&self, r2p: &mut R2Pipe, job_type_suffix: String) -> Result<()> {
        info!("Starting function metdata extraction");
        let function_details: Vec<AFIJFunctionInfo> = self.get_function_name_list(r2p)?;

        info!("Writing extracted data to file");
        let json = json!(function_details);
        self.write_to_json(&json, job_type_suffix)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        Ok(())
    }

    pub fn extract_function_variables(
        &self,
        r2p: &mut R2Pipe,
        job_type_suffix: String,
    ) -> Result<()> {
        info!("Starting function variables extraction");
        let function_details = self.get_function_name_list(r2p)?;
        let mut func_variables_vec: HashMap<String, AFVJFuncDetails> = HashMap::new();
        info!("Executing aeafj for each function");
        for function in function_details.iter() {
            let json = r2p
                .cmd(format!("afvj @ {}", &function.name).as_str())
                .with_context(|| {
                    format!(
                        "Command afvj failed in {:?} at function {:?}.",
                        self.file_path, function.name
                    )
                })?;
            let json_obj: AFVJFuncDetails = serde_json::from_str(&json)
                .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
            func_variables_vec.insert(function.name.clone(), json_obj);
        }
        info!("All functions processed");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(func_variables_vec), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_func_cfgs(&self, r2p: &mut R2Pipe, job_type_suffix: String) -> Result<()> {
        info!("Executing agfj @@f on {:?}", self.file_path);

        let json_raw = r2p.cmd("agfj @@f").with_context(|| {
            format!(
                "Failed to extract control flow graph information from {:?}.",
                self.file_path
            )
        })?;

        info!("Starting JSON fixup for {:?}", self.file_path);
        match self.fix_json_object(&json_raw) {
            Ok(json) => {
                info!("JSON fixup finished for {:?}", self.file_path);
                // If the cleaned JSON is an empty array, log an error and skip.
                if json == serde_json::Value::Array(vec![]) {
                    return Err(anyhow::anyhow!(
                        "File empty after JSON fixup - Only contains empty JSON array - {:?}",
                        self.file_path
                    ));
                } else {
                    self.write_to_json(&json, job_type_suffix)?;
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Unable to parse json for {:?}: {}: {}",
                    self.file_path,
                    json_raw,
                    e
                ));
            }
        }
        Ok(())
    }

    pub fn extract_function_xrefs(&self, r2p: &mut R2Pipe, job_type_suffix: String) -> Result<()> {
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_xrefs: HashMap<String, Vec<FunctionXrefDetails>> = HashMap::new();
        info!("Extracting xrefs for each function");
        for function in function_details.iter() {
            let ret = self
                .get_function_xref_details(function.offset, r2p)
                .with_context(|| {
                    format!("Unable to get function xrefs from {:?}", self.file_path)
                })?;
            function_xrefs.insert(function.name.clone(), ret);
        }
        info!("All functions processed");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_xrefs), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_decompilation(&self, r2p: &mut R2Pipe, job_type_suffix: String) -> Result<()> {
        info!("Starting decompilation extraction!");
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_decomp: HashMap<String, DecompJSON> = HashMap::new();

        for function in function_details.iter() {
            let ret = self.get_ghidra_decomp(function.offset, r2p);
            function_decomp.insert(function.name.clone(), ret.unwrap());
        }
        info!("Decompilation extracted successfully for all functions.");

        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_decomp), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_pcode_function(&self, r2p: &mut R2Pipe, job_type_suffix: String) -> Result<()> {
        info!("Starting pcode extraction at a function level");
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_pcode = Vec::new();

        for function in function_details.iter() {
            let ret = self.get_ghidra_pcode_function(function.offset, function.ninstrs, r2p);

            let formatted_obj = PCodeJSONWithFuncName {
                function_name: function.name.clone(),
                pcode: ret.unwrap(),
            };

            function_pcode.push(formatted_obj);
        }
        info!("Pcode extracted successfully for all functions.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_pcode), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_pcode_basic_block(
        &self,
        r2p: &mut R2Pipe,
        job_type_suffix: String,
    ) -> Result<()> {
        info!("Starting pcode extraction for each basic block in each function within the binary");
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_pcode = Vec::new();

        for function in function_details.iter() {
            let bb_addresses = self
                .get_basic_block_addresses(function.offset, r2p)
                .with_context(|| {
                    format!(
                        "Unable to get basic block addresses in {:?} at offset {:?}",
                        self.file_path, function.offset
                    )
                })?;
            let mut bb_pcode: Vec<PCodeJsonWithBB> = Vec::new();
            for bb in bb_addresses.iter() {
                let ret = self
                    .get_ghidra_pcode_function(
                        bb.addr,
                        bb.ninstr.try_into().unwrap(), // Convert u64 to i64
                        r2p,
                    )
                    .with_context(|| {
                        format!(
                            "Basic block decompilation failed in {:?} at offset {:?}",
                            self.file_path, bb.addr
                        )
                    })?;
                let pcode_json = PCodeJsonWithBB {
                    block_start_adr: bb.addr,
                    pcode: ret.pcode,
                    asm: ret.asm,
                    bb_info: bb.clone(),
                };
                bb_pcode.push(pcode_json);
            }

            function_pcode.push(PCodeJsonWithBBAndFuncName {
                function_name: function.name.clone(),
                pcode_blocks: bb_pcode,
            });
        }
        info!("Pcode extracted successfully for all functions.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_pcode), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_local_variable_xrefs(
        &self,
        r2p: &mut R2Pipe,
        job_type_suffix: String,
    ) -> Result<()> {
        info!("Starting local variable xref extraction");
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_local_variable_xrefs: HashMap<String, LocalVariableXrefs> = HashMap::new();

        for function in function_details.iter() {
            let ret = self.get_local_variable_xref_details(function.offset, r2p)?;
            function_local_variable_xrefs.insert(function.name.clone(), ret);
        }
        info!("Local variable xrefs extracted successfully for all functions.");

        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_local_variable_xrefs), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_global_strings(&self, r2p: &mut R2Pipe, job_type_suffix: String) -> Result<()> {
        info!("Starting Global String Extraction");
        let json = r2p
            .cmd("izj")
            .with_context(|| format!("Command izj failed in {:?}.", self.file_path))?;

        debug!("{}", json);
        let json_obj: Vec<StringEntry> = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;

        self.write_to_json(&json!(json_obj), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_function_zignatures(
        &self,
        r2p: &mut R2Pipe,
        job_type_suffix: String,
    ) -> Result<()> {
        info!("Starting function zignatures extraction");
        let _ = r2p
            .cmd("zg")
            .with_context(|| format!("Command zg failed in {:?}.", self.file_path))?; // generate zignatures
        debug!("Finished generating function zignatures");
        let json = r2p
            .cmd("zj")
            .with_context(|| format!("Command zj failed in {:?}.", self.file_path))?;
        let function_zignatures: Vec<FunctionZignature> = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        info!("Function zignatures extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_zignatures), job_type_suffix)?;
        Ok(())
    }

    pub fn extract_function_bytes(&self, r2p: &mut R2Pipe, job_type_suffix: String) -> Result<()> {
        info!("Starting function bytes extraction");
        let function_details = self.get_function_name_list(r2p)?;

        for function in function_details.iter() {
            debug!(
                "Function Name: {} Offset: {} Size: {}",
                function.name, function.offset, function.size
            );
            let function_bytes = self
                .get_bytes_function(function.offset, function.size, r2p)
                .with_context(|| {
                    format!(
                        "Bytes extraction failed in {:?} at function {:?}.",
                        self.file_path, function.name
                    )
                })?;
            Self::write_to_bin(
                self,
                &function.name,
                &function_bytes.bytes,
                &job_type_suffix,
            )
            .expect("Failed to write bytes to bin.");
        }
        info!("Function bytes successfully extracted");
        Ok(())
    }

    // r2 commands to structs
    fn get_bytes_function(
        &self,
        function_addr: u64,
        function_size: i128,
        r2p: &mut R2Pipe,
    ) -> Result<FuncBytes, r2pipe::Error> {
        Self::go_to_address(r2p, function_addr);
        r2p.cmd(format!("s {}", function_addr).as_str())?;
        let function_bytes = r2p.cmd(format!("p8 {}", function_size).as_str())?;
        let function_bytes = function_bytes.trim();
        let function_bytes = hex::decode(function_bytes).map_err(|e| {
            r2pipe::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Hex decode error: {}", e),
            ))
        })?;

        Ok(FuncBytes {
            bytes: function_bytes,
        })
    }

    fn get_ghidra_pcode_function(
        &self,
        function_addr: u64,
        num_instructons: i64,
        r2p: &mut R2Pipe,
    ) -> Result<PCodeJSON, r2pipe::Error> {
        Self::go_to_address(r2p, function_addr);
        let pcode_ret = r2p.cmd(format!("pdgsd {}", num_instructons).as_str())?;
        let lines = pcode_ret.lines();
        let mut asm_ins = Vec::new();
        let mut pcode_ins = Vec::new();

        for line in lines {
            if line.starts_with("0x") {
                asm_ins.push(line.trim().to_string());
            } else {
                pcode_ins.push(line.trim().to_string());
            }
        }

        Ok(PCodeJSON {
            pcode: pcode_ins,
            asm: Some(asm_ins),
        })
    }

    fn get_ghidra_decomp(
        &self,
        function_addr: u64,
        r2p: &mut R2Pipe,
    ) -> Result<DecompJSON, anyhow::Error> {
        Self::go_to_address(r2p, function_addr);
        let json = r2p.cmd("pdgj")?;

        if self.with_annotations {
            let json_obj: DecompJSON = serde_json::from_str(&json)
                .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
            Ok(json_obj)
        } else {
            let json_obj: Value = serde_json::from_str(&json)
                .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
            let parsed_code = json_obj["code"].as_str().unwrap().to_string();
            let parsed_obj = DecompJSON {
                code: parsed_code,
                annotations: Vec::new(),
            };
            Ok(parsed_obj)
        }
    }

    fn get_function_name_list(
        &self,
        r2p: &mut R2Pipe,
    ) -> Result<Vec<AFIJFunctionInfo>, anyhow::Error> {
        info!("Getting function information from binary");
        let json = r2p
            .cmd("aflj")
            .with_context(|| format!("Failed executing aflj on {:?}", self.file_path))?;

        let json_obj: Vec<AFIJFunctionInfo> = serde_json::from_str(json.as_ref())
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        Ok(json_obj)
    }

    fn get_basic_block_addresses(
        &self,
        function_addr: u64,
        r2p: &mut R2Pipe,
    ) -> Result<BasicBlockInfo, anyhow::Error> {
        info!(
            "Getting the basic block information for function @ {}",
            function_addr
        );
        Self::go_to_address(r2p, function_addr);
        // Get basic block information
        let json = r2p
            .cmd("afbj")
            .with_context(|| format!("Command afbj failed in {:?}", self.file_path))?;

        // Parse the JSON into a mutable serde_json::Value.
        let mut value: serde_json::Value = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;

        // Iterate over each object and convert "traced" from integer to boolean.
        if let Some(array) = value.as_array_mut() {
            for item in array.iter_mut() {
                if let Some(traced_value) = item.get_mut("traced") {
                    // If traced is a number, convert it to a bool.
                    if let Some(num) = traced_value.as_i64() {
                        *traced_value = serde_json::Value::Bool(num != 0);
                    }
                }
            }
        }

        // Deserialize JSON into a BasicBlockInfo struct
        let bb_addresses: BasicBlockInfo =
            serde_json::from_value(value.clone()).with_context(|| {
                format!(
                    "Unable to convert {:?} into a BasicBlockInfo struct!",
                    value
                )
            })?;
        Ok(bb_addresses)
    }

    fn get_local_variable_xref_details(
        &self,
        function_addr: u64,
        r2p: &mut R2Pipe,
    ) -> Result<LocalVariableXrefs, r2pipe::Error> {
        info!("Getting local variable xref details");
        Self::go_to_address(r2p, function_addr);
        let json = r2p.cmd("axvj");

        // Convert returned JSON into a BasicBlockInfo struct
        if let Ok(json_str) = json {
            let local_variable_xrefs: LocalVariableXrefs = serde_json::from_str(json_str.as_ref())
                .expect("Unable to convert returned object into a BasicBlockInfo struct!");
            Ok(local_variable_xrefs)
        } else {
            Err(json.unwrap_err())
        }
    }

    fn get_function_xref_details(
        &self,
        function_addr: u64,
        r2p: &mut R2Pipe,
    ) -> Result<Vec<FunctionXrefDetails>, anyhow::Error> {
        info!("Getting function xref details");
        Self::go_to_address(r2p, function_addr);
        let json = r2p
            .cmd("axffj")
            .with_context(|| format!("Command axffj failed in {:?}", self.file_path))?;
        let mut json_obj: Vec<FunctionXrefDetails> = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        debug!("Replacing all CALL xrefs with actual function name");
        // TODO: There is a minor bug in this where functions without any xrefs are included.
        // Been left in as may be useful later down the line.
        if !json_obj.is_empty() {
            debug!("Replacing all CALL xrefs with actual function name");
            for element in json_obj.iter_mut() {
                if element.type_field == "CALL" {
                    let cmd_str = format!("afi. @ {}", &element.ref_field);
                    let function_name = r2p.cmd(cmd_str.as_str()).with_context(|| {
                        format!("Command {:?} failed in {:?}", cmd_str, self.file_path)
                    })?;
                    element.name = function_name.trim().to_string();
                }
            }
        };
        Ok(json_obj)
    }

    // Helper Functions
    fn fix_json_object(&self, json_raw: &str) -> Result<serde_json::Value, serde_json::Error> {
        // Collect all JSON objects into a vector.
        let stream = Deserializer::from_str(json_raw).into_iter::<Value>();
        let json_objects: Result<Vec<Value>, _> = stream
            .filter_map(|result| {
                match result {
                    Ok(Value::Array(ref arr)) if arr.is_empty() => None, // skip empty arrays
                    other => Some(other),
                }
            })
            .collect();
        // Map the collected vector into a JSON array.
        json_objects.map(Value::Array)
    }

    fn sanitize_function_name(&self, original: &str) -> String {
        // Replace non-valid characters with '_'
        // Valid characters: letters, digits, '_', '-', and '.'
        let re = Regex::new(r"[^\w.-]").unwrap();
        re.replace_all(original, "_").into_owned()
    }

    fn get_file_name(&self) -> Result<String> {
        self.file_path
            .file_name()
            .ok_or_else(|| anyhow!("Unable to get file name from {:?}", self.file_path))
            .map(|os_str| os_str.to_string_lossy().to_string())
    }

    fn write_to_json(&self, json_obj: &Value, job_type_suffix: String) -> Result<()> {
        let mut fp_filename = self.get_file_name()?;

        fp_filename = if self.with_annotations {
            fp_filename + "_" + &job_type_suffix + "_annotations" + ".json"
        } else {
            fp_filename + "_" + &job_type_suffix + ".json"
        };

        let mut output_filepath = PathBuf::new();
        output_filepath.push(self.output_path.clone());
        output_filepath.push(fp_filename);
        debug!("Save filename: {:?}", output_filepath);

        let file = File::create(&output_filepath)
            .with_context(|| format!("Unable to create file {:?}", output_filepath))?;
        serde_json::to_writer(&file, &json_obj)
            .with_context(|| format!("Failed to write JSON to {:?}", output_filepath))?;

        Ok(())
    }

    fn write_to_bin(
        &self,
        function_name: &String,
        func_bytes: &[u8],
        dirname_suffix: &String,
    ) -> Result<()> {
        // Extract the file stem from self.file_path and add context if missing.
        let file_stem = self.get_file_name()?;

        // Construct the full output directory path.
        let mut output_dir = self.output_path.clone();
        // Build the directory name by combining the file stem with the given suffix.
        let dir_name = format!("{}_{}", file_stem, dirname_suffix);
        output_dir.push(&dir_name);

        if !output_dir.is_dir() {
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("Failed to create directory {:?}", output_dir))?;
        }

        // Construct the full output file path.
        let mut output_filepath = output_dir.clone();
        // Sanitize the function name to create a valid filename.
        let sanitized_function_name = self.sanitize_function_name(function_name);

        // If sanitized_function_name larger than 100 characters, snip
        let sanitized_function_name = if sanitized_function_name.len() > 100 {
            String::from(&sanitized_function_name[0..75])
        } else {
            sanitized_function_name
        };

        let file_name = format!("{}.bin", sanitized_function_name);
        output_filepath.push(file_name);

        // Check if a file with same name the sanitized name already exists.
        if output_filepath.exists() {
            debug!(
                "Duplicate function binary file detected for '{}' at {:?}. Skipping.",
                function_name, output_filepath
            );
            return Ok(());
        }

        debug!(
            "Attempting to write function bytes to {:?}",
            output_filepath
        );
        // Write the file and attach context on error.
        fs::write(&output_filepath, func_bytes)
            .with_context(|| format!("Failed to write file {:?}", output_filepath))?;

        Ok(())
    }

    fn go_to_address(r2p: &mut R2Pipe, function_addr: u64) {
        r2p.cmd(format!("s {}", function_addr).as_str())
            .expect("failed to seek addr");
    }

    fn handle_symbols_pdb(&self, r2p: &mut R2Pipe) -> Result<(), Error> {
        // Download symbols if available
        debug!("Downloading pdb file for {:?}", self.file_path);
        let download_pdb = r2p.cmd("idpd");

        debug!("Download PDB Ret: {:?}", download_pdb);

        if download_pdb.unwrap().contains("success") {
            let ret = r2p.cmd("idp");
            debug!("Return value: {:?}", ret);

            Ok(())
        } else {
            Err(anyhow!("Unable to download pdb"))
        }
    }

    fn setup_r2_pipe(&self) -> R2Pipe {
        if self.r2p_config.use_curl_pdb {
            // Docs suggest this is unsafe
            env::set_var("R2_CURL", "1");
        }

        let opts = if self.r2p_config.debug {
            debug!("Creating r2 handle with debugging");
            R2PipeSpawnOptions {
                exepath: "radare2".to_owned(),
                args: vec!["-e bin.cache=true", "-e log.level=0", "-e asm.pseudo=true"],
            }
        } else {
            debug!("Creating r2 handle without debugging");
            R2PipeSpawnOptions {
                exepath: "radare2".to_owned(),
                args: vec![
                    "-e bin.cache=true",
                    "-e log.level=1",
                    "-2",
                    "-e asm.pseudo=true",
                ],
            }
        };

        debug!("Attempting to create r2pipe using {:?}", self.file_path);
        let mut r2p = match R2Pipe::in_session() {
            Some(_) => R2Pipe::open().expect("Unable to open R2Pipe"),
            None => R2Pipe::spawn(self.file_path.to_str().unwrap(), Some(opts))
                .expect("Failed to spawn new R2Pipe"),
        };

        if self.r2p_config.use_curl_pdb {
            let info = r2p.cmdj("ij");
            if info.is_ok() {
                let info = info.unwrap();
                if info["bin"]["bintype"].as_str().unwrap() == "pe" {
                    debug!("PE file found. Handling symbol download!");
                    let ret = self.handle_symbols_pdb(&mut r2p);

                    if ret.is_err() {
                        error!("Unable to get PDB info")
                    }
                }
            }
        }

        r2p
    }

    fn analyse_r2_pipe(&self, r2p: &mut R2Pipe) {
        if self.r2p_config.extended_analysis {
            debug!(
                "Executing 'aaa' r2 command for {}",
                self.file_path.display()
            );
            r2p.cmd("aaa")
                .expect("Unable to complete standard analysis!");
            debug!("'aaa' r2 command complete for {}", self.file_path.display());
        } else {
            debug!("Executing 'aa' r2 command for {}", self.file_path.display());
            r2p.cmd("aa")
                .expect("Unable to complete standard analysis!");
            debug!(
                "'aa' r2 command complete for {:?}",
                self.file_path.display()
            );
        };
    }
}
