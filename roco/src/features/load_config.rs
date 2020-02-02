use roki::containers::LoadConfigContainer;
use roki::Executable;

pub fn print(executable: &Executable) -> () {
    let load_config_data: &LoadConfigContainer = match executable.load_config_data() {
        Some(load_config_data) => load_config_data,
        None => return,
    };

    let directory = load_config_data.directory();
    let integrity = directory.code_integrity();

    println!(
        "
LOAD CONFIGURATION
    size                                            : {:#010X}
    time date stamps                                : {:#010X}
    version                                         : {}.{}
    global flags clear                              : {:#010X}
    global flags set                                : {:#010X}
    critical section default timeout                : {:#010X}
    de-commit free block threshold                  : {:#018X}
    de-commit total free threshold                  : {:#018X}
    lock prefix table                               : {:#018X}
    maximum allocation size                         : {:#018X}
    virtual memory threshold                        : {:#018X}
    process affinity mask                           : {:#018X}
    process heap flags                              : {:#010X}
    csd version                                     : {}
    dependent load flags                            : {:#06X}
    edit list                                       : {:#018X}
    security cookie                                 : {:#018X}
    se handler table                                : {:#018X}
    se handler count                                : {:#018X}
    guard cf check function pointer                 : {:#018X}
    guard cf dispatch function pointer              : {:#018X}
    guard cf function table                         : {:#018X}
    guard cf function count                         : {:#018X}
    guard flags                                     : {:#010X}
    code integrity flags/catalog                    : {:#06X} / {:#06X}
    code integrity catalog offset                   : {:#010X}
    guard address taken IAT entry table             : {:#018X}
    guard address taken IAT entry count             : {:#018X}
    guard long jump target table                    : {:#018X}
    guard long jump target count                    : {:#018X}
    dynamic value reloc table                       : {:#018X}
    chpe metadata pointer                           : {:#018X}
    guard rf failure routine                        : {:#018X}
    guard rf failure routine function pointer       : {:#018X}
    dynamic value reloc table offset                : {:#010X}
    dynamic value reloc table section               : {:#06X}
    guard rf verify stack pointer function pointer  : {:#018X}
    hot patch table offset                          : {:#010X}
    enclave configuration pointer                   : {:#018X}
    volatile metadata pointer                       : {:#018X}\
    ",
        directory.size(),
        directory.time_date_stamp(),
        directory.major_version(),
        directory.minor_version(),
        directory.global_flags_clear(),
        directory.global_flags_set(),
        directory.critical_section_default_timeout(),
        directory.de_commit_free_block_threshold(),
        directory.de_commit_total_free_threshold(),
        directory.lock_prefix_table(),
        directory.maximum_allocation_size(),
        directory.virtual_memory_threshold(),
        directory.process_affinity_mask(),
        directory.process_heap_flags(),
        directory.csd_version(),
        directory.dependent_load_flags(),
        directory.edit_list(),
        directory.security_cookie(),
        directory.se_handler_table(),
        directory.se_handler_count(),
        directory.guard_cf_check_function_pointer(),
        directory.guard_cf_dispatch_function_pointer(),
        directory.guard_cf_function_table(),
        directory.guard_cf_function_count(),
        directory.guard_flags(),
        integrity.flags(),
        integrity.catalog(),
        integrity.catalog_offset(),
        directory.guard_address_taken_iat_entry_table(),
        directory.guard_address_taken_iat_entry_count(),
        directory.guard_long_jump_target_table(),
        directory.guard_long_jump_target_count(),
        directory.dynamic_value_reloc_table(),
        directory.chpe_metadata_pointer(),
        directory.guard_rf_failure_routine(),
        directory.guard_rf_failure_routine_function_pointer(),
        directory.dynamic_value_reloc_table_offset(),
        directory.dynamic_value_reloc_table_section(),
        directory.guard_rf_verify_stack_pointer_function_pointer(),
        directory.hot_patch_table_offset(),
        directory.enclave_configuration_pointer(),
        directory.volatile_metadata_pointer(),
    );
}
