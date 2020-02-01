use scroll::{Pread, LE};

use crate::Executable;

#[derive(Debug, Pread)]
pub struct LoadConfigCodeIntegrity {
    flags: u16,
    catalog: u16,
    catalog_offset: u32,
    reserved: u32,
}

impl LoadConfigCodeIntegrity {
    pub fn catalog(&self) -> u16 {
        self.catalog
    }

    pub fn catalog_offset(&self) -> u32 {
        self.catalog_offset
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }
}

#[derive(Debug, Pread)]
pub struct LoadConfigDirectory32 {
    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u32,
    de_commit_total_free_threshold: u32,
    lock_prefix_table: u32,
    maximum_allocation_size: u32,
    virtual_memory_threshold: u32,
    process_heap_flags: u32,
    process_affinity_mask: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u32,
    security_cookie: u32,
    se_handler_table: u32,
    se_handler_count: u32,
    guard_cf_check_function_pointer: u32,
    guard_cf_dispatch_function_pointer: u32,
    guard_cf_function_table: u32,
    guard_cf_function_count: u32,
    guard_flags: u32,
    code_integrity: LoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u32,
    guard_address_taken_iat_entry_count: u32,
    guard_long_jump_target_table: u32,
    guard_long_jump_target_count: u32,
    dynamic_value_reloc_table: u32,
    chpe_metadata_pointer: u32,
    guard_rf_failure_routine: u32,
    guard_rf_failure_routine_function_pointer: u32,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u32,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u32,
    volatile_metadata_pointer: u32,
}

#[derive(Debug, Pread)]
pub struct LoadConfigDirectory64 {
    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u64,
    de_commit_total_free_threshold: u64,
    lock_prefix_table: u64,
    maximum_allocation_size: u64,
    virtual_memory_threshold: u64,
    process_affinity_mask: u64,
    process_heap_flags: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u64,
    security_cookie: u64,
    se_handler_table: u64,
    se_handler_count: u64,
    guard_cf_check_function_pointer: u64,
    guard_cf_dispatch_function_pointer: u64,
    guard_cf_function_table: u64,
    guard_cf_function_count: u64,
    guard_flags: u32,
    code_integrity: LoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u64,
    guard_address_taken_iat_entry_count: u64,
    guard_long_jump_target_table: u64,
    guard_long_jump_target_count: u64,
    dynamic_value_reloc_table: u64,
    chpe_metadata_pointer: u64,
    guard_rf_failure_routine: u64,
    guard_rf_failure_routine_function_pointer: u64,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u64,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u64,
    volatile_metadata_pointer: u64,
}

#[derive(Debug)]
pub struct LoadConfigDirectory {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u64,
    de_commit_total_free_threshold: u64,
    lock_prefix_table: u64,
    maximum_allocation_size: u64,
    virtual_memory_threshold: u64,
    process_affinity_mask: u64,
    process_heap_flags: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u64,
    security_cookie: u64,
    se_handler_table: u64,
    se_handler_count: u64,
    guard_cf_check_function_pointer: u64,
    guard_cf_dispatch_function_pointer: u64,
    guard_cf_function_table: u64,
    guard_cf_function_count: u64,
    guard_flags: u32,
    code_integrity: LoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u64,
    guard_address_taken_iat_entry_count: u64,
    guard_long_jump_target_table: u64,
    guard_long_jump_target_count: u64,
    dynamic_value_reloc_table: u64,
    chpe_metadata_pointer: u64,
    guard_rf_failure_routine: u64,
    guard_rf_failure_routine_function_pointer: u64,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u64,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u64,
    volatile_metadata_pointer: u64,
}

impl LoadConfigDirectory {
    pub fn parse(executable: &Executable, offset: usize) -> Result<Self, failure::Error> {
        let directory = if executable.is_x64() {
            LoadConfigDirectory::from_load_config_directory_64(executable.buffer().pread_with::<LoadConfigDirectory64>(offset, LE).map_err(|_| {
                let msg = format!("Failed to read the IMAGE_LOAD_CONFIG_DIRECTORY64 at {:#010X}", offset);
                return failure::err_msg(msg);
            })?)
        } else {
            LoadConfigDirectory::from_load_config_directory_32(executable.buffer().pread_with::<LoadConfigDirectory32>(offset, LE).map_err(|_| {
                let msg = format!("Failed to read the IMAGE_LOAD_CONFIG_DIRECTORY32 at {:#010X}", offset);
                return failure::err_msg(msg);
            })?)
        };

        Ok(directory)
    }

    fn from_load_config_directory_32(cfg: LoadConfigDirectory32) -> Self {
        LoadConfigDirectory {
            size: cfg.size,
            time_date_stamp: cfg.time_date_stamp,
            major_version: cfg.major_version,
            minor_version: cfg.minor_version,
            global_flags_clear: cfg.global_flags_clear,
            global_flags_set: cfg.global_flags_set,
            critical_section_default_timeout: cfg.critical_section_default_timeout,
            de_commit_free_block_threshold: cfg.de_commit_free_block_threshold as u64,
            de_commit_total_free_threshold: cfg.de_commit_total_free_threshold as u64,
            lock_prefix_table: cfg.lock_prefix_table as u64,
            maximum_allocation_size: cfg.maximum_allocation_size as u64,
            virtual_memory_threshold: cfg.virtual_memory_threshold as u64,
            process_affinity_mask: cfg.process_affinity_mask as u64,
            process_heap_flags: cfg.process_heap_flags,
            csd_version: cfg.csd_version,
            dependent_load_flags: cfg.dependent_load_flags,
            edit_list: cfg.edit_list as u64,
            security_cookie: cfg.security_cookie as u64,
            se_handler_table: cfg.se_handler_table as u64,
            se_handler_count: cfg.se_handler_count as u64,
            guard_cf_check_function_pointer: cfg.guard_cf_check_function_pointer as u64,
            guard_cf_dispatch_function_pointer: cfg.guard_cf_dispatch_function_pointer as u64,
            guard_cf_function_table: cfg.guard_cf_function_table as u64,
            guard_cf_function_count: cfg.guard_cf_function_count as u64,
            guard_flags: cfg.guard_flags,
            code_integrity: cfg.code_integrity,
            guard_address_taken_iat_entry_table: cfg.guard_address_taken_iat_entry_table as u64,
            guard_address_taken_iat_entry_count: cfg.guard_address_taken_iat_entry_count as u64,
            guard_long_jump_target_table: cfg.guard_long_jump_target_table as u64,
            guard_long_jump_target_count: cfg.guard_long_jump_target_count as u64,
            dynamic_value_reloc_table: cfg.dynamic_value_reloc_table as u64,
            chpe_metadata_pointer: cfg.chpe_metadata_pointer as u64,
            guard_rf_failure_routine: cfg.guard_rf_failure_routine as u64,
            guard_rf_failure_routine_function_pointer: cfg.guard_rf_failure_routine_function_pointer as u64,
            dynamic_value_reloc_table_offset: cfg.dynamic_value_reloc_table_offset,
            dynamic_value_reloc_table_section: cfg.dynamic_value_reloc_table_section,
            reserved2: cfg.reserved2,
            guard_rf_verify_stack_pointer_function_pointer: cfg.guard_rf_verify_stack_pointer_function_pointer as u64,
            hot_patch_table_offset: cfg.hot_patch_table_offset,
            reserved3: cfg.reserved3,
            enclave_configuration_pointer: cfg.enclave_configuration_pointer as u64,
            volatile_metadata_pointer: cfg.volatile_metadata_pointer as u64,
        }
    }

    fn from_load_config_directory_64(cfg: LoadConfigDirectory64) -> Self {
        LoadConfigDirectory {
            size: cfg.size,
            time_date_stamp: cfg.time_date_stamp,
            major_version: cfg.major_version,
            minor_version: cfg.minor_version,
            global_flags_clear: cfg.global_flags_clear,
            global_flags_set: cfg.global_flags_set,
            critical_section_default_timeout: cfg.critical_section_default_timeout,
            de_commit_free_block_threshold: cfg.de_commit_free_block_threshold,
            de_commit_total_free_threshold: cfg.de_commit_total_free_threshold,
            lock_prefix_table: cfg.lock_prefix_table,
            maximum_allocation_size: cfg.maximum_allocation_size,
            virtual_memory_threshold: cfg.virtual_memory_threshold,
            process_affinity_mask: cfg.process_affinity_mask,
            process_heap_flags: cfg.process_heap_flags,
            csd_version: cfg.csd_version,
            dependent_load_flags: cfg.dependent_load_flags,
            edit_list: cfg.edit_list,
            security_cookie: cfg.security_cookie,
            se_handler_table: cfg.se_handler_table,
            se_handler_count: cfg.se_handler_count,
            guard_cf_check_function_pointer: cfg.guard_cf_check_function_pointer,
            guard_cf_dispatch_function_pointer: cfg.guard_cf_dispatch_function_pointer,
            guard_cf_function_table: cfg.guard_cf_function_table,
            guard_cf_function_count: cfg.guard_cf_function_count,
            guard_flags: cfg.guard_flags,
            code_integrity: cfg.code_integrity,
            guard_address_taken_iat_entry_table: cfg.guard_address_taken_iat_entry_table,
            guard_address_taken_iat_entry_count: cfg.guard_address_taken_iat_entry_count,
            guard_long_jump_target_table: cfg.guard_long_jump_target_table,
            guard_long_jump_target_count: cfg.guard_long_jump_target_count,
            dynamic_value_reloc_table: cfg.dynamic_value_reloc_table,
            chpe_metadata_pointer: cfg.chpe_metadata_pointer,
            guard_rf_failure_routine: cfg.guard_rf_failure_routine,
            guard_rf_failure_routine_function_pointer: cfg.guard_rf_failure_routine_function_pointer,
            dynamic_value_reloc_table_offset: cfg.dynamic_value_reloc_table_offset,
            dynamic_value_reloc_table_section: cfg.dynamic_value_reloc_table_section,
            reserved2: cfg.reserved2,
            guard_rf_verify_stack_pointer_function_pointer: cfg.guard_rf_verify_stack_pointer_function_pointer,
            hot_patch_table_offset: cfg.hot_patch_table_offset,
            reserved3: cfg.reserved3,
            enclave_configuration_pointer: cfg.enclave_configuration_pointer,
            volatile_metadata_pointer: cfg.volatile_metadata_pointer,
        }
    }

    pub fn chpe_metadata_pointer(&self) -> u64 {
        self.chpe_metadata_pointer
    }

    pub fn code_integrity(&self) -> &LoadConfigCodeIntegrity {
        &self.code_integrity
    }

    pub fn critical_section_default_timeout(&self) -> u32 {
        self.critical_section_default_timeout
    }

    pub fn csd_version(&self) -> u16 {
        self.csd_version
    }

    pub fn de_commit_free_block_threshold(&self) -> u64 {
        self.de_commit_free_block_threshold
    }

    pub fn de_commit_total_free_threshold(&self) -> u64 {
        self.de_commit_total_free_threshold
    }

    pub fn edit_list(&self) -> u64 {
        self.edit_list
    }

    pub fn enclave_configuration_pointer(&self) -> u64 {
        self.enclave_configuration_pointer
    }

    pub fn dependent_load_flags(&self) -> u16 {
        self.dependent_load_flags
    }

    pub fn dynamic_value_reloc_table(&self) -> u64 {
        self.dynamic_value_reloc_table
    }

    pub fn dynamic_value_reloc_table_offset(&self) -> u32 {
        self.dynamic_value_reloc_table_offset
    }

    pub fn dynamic_value_reloc_table_section(&self) -> u16 {
        self.dynamic_value_reloc_table_section
    }

    pub fn global_flags_clear(&self) -> u32 {
        self.global_flags_clear
    }

    pub fn global_flags_set(&self) -> u32 {
        self.global_flags_set
    }

    pub fn guard_address_taken_iat_entry_count(&self) -> u64 {
        self.guard_address_taken_iat_entry_count
    }

    pub fn guard_address_taken_iat_entry_table(&self) -> u64 {
        self.guard_address_taken_iat_entry_table
    }

    pub fn guard_cf_check_function_pointer(&self) -> u64 {
        self.guard_cf_check_function_pointer
    }

    pub fn guard_cf_dispatch_function_pointer(&self) -> u64 {
        self.guard_cf_dispatch_function_pointer
    }

    pub fn guard_cf_function_count(&self) -> u64 {
        self.guard_cf_function_count
    }

    pub fn guard_cf_function_table(&self) -> u64 {
        self.guard_cf_function_table
    }

    pub fn guard_flags(&self) -> u32 {
        self.guard_flags
    }

    pub fn guard_long_jump_target_count(&self) -> u64 {
        self.guard_long_jump_target_count
    }

    pub fn guard_long_jump_target_table(&self) -> u64 {
        self.guard_long_jump_target_table
    }

    pub fn guard_rf_failure_routine(&self) -> u64 {
        self.guard_rf_failure_routine
    }

    pub fn guard_rf_failure_routine_function_pointer(&self) -> u64 {
        self.guard_rf_failure_routine_function_pointer
    }

    pub fn guard_rf_verify_stack_pointer_function_pointer(&self) -> u64 {
        self.guard_rf_verify_stack_pointer_function_pointer
    }

    pub fn hot_patch_table_offset(&self) -> u32 {
        self.hot_patch_table_offset
    }

    pub fn lock_prefix_table(&self) -> u64 {
        self.lock_prefix_table
    }

    pub fn major_version(&self) -> u16 {
        self.major_version
    }

    pub fn maximum_allocation_size(&self) -> u64 {
        self.maximum_allocation_size
    }

    pub fn minor_version(&self) -> u16 {
        self.minor_version
    }

    pub fn process_affinity_mask(&self) -> u64 {
        self.process_affinity_mask
    }

    pub fn process_heap_flags(&self) -> u32 {
        self.process_heap_flags
    }

    pub fn se_handler_count(&self) -> u64 {
        self.se_handler_count
    }

    pub fn se_handler_table(&self) -> u64 {
        self.se_handler_table
    }

    pub fn security_cookie(&self) -> u64 {
        self.security_cookie
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    pub fn virtual_memory_threshold(&self) -> u64 {
        self.virtual_memory_threshold
    }

    pub fn volatile_metadata_pointer(&self) -> u64 {
        self.volatile_metadata_pointer
    }
}
