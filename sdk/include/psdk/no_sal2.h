/*
 * PROJECT:     ReactOS PSDK
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Renders the SAL annotations for documenting APIs harmless.
 * COPYRIGHT:   Microsoft Corporation.
 * SOURCE:      https://github.com/microsoft/ChakraCore/blob/master/pal/inc/rt/no_sal2.h
 */
//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information. 
//

    
/***
*       no_sal2.h - renders the SAL annotations for documenting APIs harmless.
*

*
*Purpose:
*       sal.h provides a set of SAL2 annotations to describe how a function uses its
*       parameters - the assumptions it makes about them, and the guarantees it makes
*       upon finishing. This file redefines all those annotation macros to be harmless.
*       It is designed for use in down-level build environments where the tooling may
*       be unhappy with the standard SAL2 macro definitions.
*
*       [Public]
*

*
****/

#ifndef _NO_SAL_2_H_
#define _NO_SAL_2_H_

#undef __notnull
#define __notnull
#undef _When_
#define _When_(c,a)
#undef _At_
#define _At_(t,a)
#undef _At_buffer_
#define _At_buffer_(t,i,c,a)
#undef _Group_
#define _Group_(a)
#undef _Pre_
#define _Pre_
#undef _Post_
#define _Post_
#undef _Deref_
#define _Deref_
#undef _Null_
#define _Null_
#undef _Notnull_
#define _Notnull_
#undef _Maybenull_
#define _Maybenull_
#undef _Const_
#define _Const_
#undef _Check_return_
#define _Check_return_
#undef _Must_inspect_result_
#define _Must_inspect_result_
#undef _Pre_satisfies_
#define _Pre_satisfies_(e)
#undef _Post_satisfies_
#define _Post_satisfies_(e)
#undef _Writable_elements_
#define _Writable_elements_(s)
#undef _Writable_bytes_
#define _Writable_bytes_(s)
#undef _Readable_elements_
#define _Readable_elements_(s)
#undef _Readable_bytes_
#define _Readable_bytes_(s)
#undef _Null_terminated_
#define _Null_terminated_
#undef _NullNull_terminated_
#define _NullNull_terminated_
#undef _Valid_
#define _Valid_
#undef _Notvalid_
#define _Notvalid_
#undef _Success_
#define _Success_(c)
#undef _Return_type_success_
#define _Return_type_success_(c)
#undef _On_failure_
#define _On_failure_(a)
#undef _Always_
#define _Always_(a)
#undef _Use_decl_annotations_
#define _Use_decl_annotations_
#undef _Pre_defensive_
#define _Pre_defensive_
#undef _Post_defensive_
#define _Post_defensive_
#undef _Pre_unknown_
#define _Pre_unknown_
#undef _Acquires_lock_
#define _Acquires_lock_(e)
#undef _Releases_lock_
#define _Releases_lock_(e)
#undef _Requires_lock_held_
#define _Requires_lock_held_(e)
#undef _Requires_lock_not_held_
#define _Requires_lock_not_held_(e)
#undef _Requires_no_locks_held_
#define _Requires_no_locks_held_
#undef _Guarded_by_
#define _Guarded_by_(e)
#undef _Write_guarded_by_
#define _Write_guarded_by_(e)
#undef _Interlocked_
#define _Interlocked_
#undef _Post_same_lock_
#define _Post_same_lock_(e1,e2)
#undef _Benign_race_begin_
#define _Benign_race_begin_
#undef _Benign_race_end_
#define _Benign_race_end_
#undef _No_competing_thread_
#define _No_competing_thread_
#undef _No_competing_thread_begin_
#define _No_competing_thread_begin_
#undef _No_competing_thread_end_
#define _No_competing_thread_end_
#undef _Acquires_shared_lock_
#define _Acquires_shared_lock_(e)
#undef _Releases_shared_lock_
#define _Releases_shared_lock_(e)
#undef _Requires_shared_lock_held_
#define _Requires_shared_lock_held_(e)
#undef _Acquires_exclusive_lock_
#define _Acquires_exclusive_lock_(e)
#undef _Releases_exclusive_lock_
#define _Releases_exclusive_lock_(e)
#undef _Requires_exclusive_lock_held_
#define _Requires_exclusive_lock_held_(e)
#undef _Has_lock_kind_
#define _Has_lock_kind_(n)
#undef _Create_lock_level_
#define _Create_lock_level_(n)
#undef _Has_lock_level_
#define _Has_lock_level_(n)
#undef _Lock_level_order_
#define _Lock_level_order_(n1,n2)
#undef _Analysis_assume_lock_acquired_
#define _Analysis_assume_lock_acquired_(e)
#undef _Analysis_assume_lock_released_
#define _Analysis_assume_lock_released_(e)
#undef _Analysis_assume_lock_held_
#define _Analysis_assume_lock_held_(e)
#undef _Analysis_assume_lock_not_held_
#define _Analysis_assume_lock_not_held_(e)
#undef _Analysis_assume_same_lock_
#define _Analysis_assume_same_lock_(e)
#undef _In_
#define _In_
#undef _Out_
#define _Out_
#undef _Inout_
#define _Inout_
#undef _In_z_
#define _In_z_
#undef _Inout_z_
#define _Inout_z_
#undef _In_reads_
#define _In_reads_(s)
#undef _In_reads_bytes_
#define _In_reads_bytes_(s)
#undef _In_reads_z_
#define _In_reads_z_(s)
#undef _In_reads_or_z_
#define _In_reads_or_z_(s)
#undef _Out_writes_
#define _Out_writes_(s)
#undef _Out_writes_bytes_
#define _Out_writes_bytes_(s)
#undef _Out_writes_z_
#define _Out_writes_z_(s)
#undef _Inout_updates_
#define _Inout_updates_(s)
#undef _Inout_updates_bytes_
#define _Inout_updates_bytes_(s)
#undef _Inout_updates_z_
#define _Inout_updates_z_(s)
#undef _Out_writes_to_
#define _Out_writes_to_(s,c)
#undef _Out_writes_bytes_to_
#define _Out_writes_bytes_to_(s,c)
#undef _Out_writes_all_
#define _Out_writes_all_(s)
#undef _Out_writes_bytes_all_
#define _Out_writes_bytes_all_(s)
#undef _Inout_updates_to_
#define _Inout_updates_to_(s,c)
#undef _Inout_updates_bytes_to_
#define _Inout_updates_bytes_to_(s,c)
#undef _Inout_updates_all_
#define _Inout_updates_all_(s)
#undef _Inout_updates_bytes_all_
#define _Inout_updates_bytes_all_(s)
#undef _In_reads_to_ptr_
#define _In_reads_to_ptr_(p)
#undef _In_reads_to_ptr_z_
#define _In_reads_to_ptr_z_(p)
#undef _Out_writes_to_ptr_
#define _Out_writes_to_ptr_(p)
#undef _Out_writes_to_ptr_z_
#define _Out_writes_to_ptr_z_(p)
#undef _In_opt_
#define _In_opt_
#undef _Out_opt_
#define _Out_opt_
#undef _Inout_opt_
#define _Inout_opt_
#undef _In_opt_z_
#define _In_opt_z_
#undef _Inout_opt_z_
#define _Inout_opt_z_
#undef _In_reads_opt_
#define _In_reads_opt_(s)
#undef _In_reads_bytes_opt_
#define _In_reads_bytes_opt_(s)
#undef _Out_writes_opt_
#define _Out_writes_opt_(s)
#undef _Out_writes_bytes_opt_
#define _Out_writes_bytes_opt_(s)
#undef _Out_writes_opt_z_
#define _Out_writes_opt_z_(s)
#undef _Inout_updates_opt_
#define _Inout_updates_opt_(s)
#undef _Inout_updates_bytes_opt_
#define _Inout_updates_bytes_opt_(s)
#undef _Inout_updates_opt_z_
#define _Inout_updates_opt_z_(s)
#undef _Out_writes_to_opt_
#define _Out_writes_to_opt_(s,c)
#undef _Out_writes_bytes_to_opt_
#define _Out_writes_bytes_to_opt_(s,c)
#undef _Out_writes_all_opt_
#define _Out_writes_all_opt_(s)
#undef _Out_writes_bytes_all_opt_
#define _Out_writes_bytes_all_opt_(s)
#undef _Inout_updates_to_opt_
#define _Inout_updates_to_opt_(s,c)
#undef _Inout_updates_bytes_to_opt_
#define _Inout_updates_bytes_to_opt_(s,c)
#undef _Inout_updates_all_opt_
#define _Inout_updates_all_opt_(s)
#undef _Inout_updates_bytes_all_opt_
#define _Inout_updates_bytes_all_opt_(s)
#undef _In_reads_to_ptr_opt_
#define _In_reads_to_ptr_opt_(p)
#undef _In_reads_to_ptr_opt_z_
#define _In_reads_to_ptr_opt_z_(p)
#undef _Out_writes_to_ptr_opt_
#define _Out_writes_to_ptr_opt_(p)
#undef _Out_writes_to_ptr_opt_z_
#define _Out_writes_to_ptr_opt_z_(p)
#undef _Outptr_
#define _Outptr_
#undef _Outptr_opt_
#define _Outptr_opt_
#undef _Outptr_result_maybenull_
#define _Outptr_result_maybenull_
#undef _Outptr_opt_result_maybenull_
#define _Outptr_opt_result_maybenull_
#undef _Outptr_z_
#define _Outptr_z_
#undef _Outptr_opt_z_
#define _Outptr_opt_z_
#undef _Outptr_result_maybenull_z_
#define _Outptr_result_maybenull_z_
#undef _Outptr_opt_result_maybenull_z_
#define _Outptr_opt_result_maybenull_z_
#undef _COM_Outptr_
#define _COM_Outptr_
#undef _COM_Outptr_opt_
#define _COM_Outptr_opt_
#undef _COM_Outptr_result_maybenull_
#define _COM_Outptr_result_maybenull_
#undef _COM_Outptr_opt_result_maybenull_
#define _COM_Outptr_opt_result_maybenull_
#undef _Outptr_result_buffer_
#define _Outptr_result_buffer_(s)
#undef _Outptr_result_bytebuffer_
#define _Outptr_result_bytebuffer_(s)
#undef _Outptr_opt_result_buffer_
#define _Outptr_opt_result_buffer_(s)
#undef _Outptr_opt_result_bytebuffer_
#define _Outptr_opt_result_bytebuffer_(s)
#undef _Outptr_result_buffer_to_
#define _Outptr_result_buffer_to_(s,c)
#undef _Outptr_result_bytebuffer_to_
#define _Outptr_result_bytebuffer_to_(s,c)
#undef _Outptr_opt_result_buffer_to_
#define _Outptr_opt_result_buffer_to_(s,c)
#undef _Outptr_opt_result_bytebuffer_to_
#define _Outptr_opt_result_bytebuffer_to_(s,c)
#undef _Ret_
#define _Ret_
#undef _Ret_valid_
#define _Ret_valid_
#undef _Ret_z_
#define _Ret_z_
#undef _Ret_writes_
#define _Ret_writes_(s)
#undef _Ret_writes_bytes_
#define _Ret_writes_bytes_(s)
#undef _Ret_writes_z_
#define _Ret_writes_z_(s)
#undef _Ret_writes_to_
#define _Ret_writes_to_(s,c)
#undef _Ret_writes_bytes_to_
#define _Ret_writes_bytes_to_(s,c)
#undef _Ret_writes_maybenull_
#define _Ret_writes_maybenull_(s)
#undef _Ret_writes_bytes_maybenull_
#define _Ret_writes_bytes_maybenull_(s)
#undef _Ret_writes_to_maybenull_
#define _Ret_writes_to_maybenull_(s,c)
#undef _Ret_writes_bytes_to_maybenull_
#define _Ret_writes_bytes_to_maybenull_(s,c)
#undef _Ret_writes_maybenull_z_
#define _Ret_writes_maybenull_z_(s)
#undef _Ret_maybenull_
#define _Ret_maybenull_
#undef _Ret_maybenull_z_
#define _Ret_maybenull_z_
#undef _Field_size_
#define _Field_size_(s)
#undef _Field_size_opt_
#define _Field_size_opt_(s)
#undef _Field_size_bytes_
#define _Field_size_bytes_(s)
#undef _Field_size_bytes_opt_
#define _Field_size_bytes_opt_(s)
#undef _Field_size_part_
#define _Field_size_part_(s,c)
#undef _Field_size_part_opt_
#define _Field_size_part_opt_(s,c)
#undef _Field_size_bytes_part_
#define _Field_size_bytes_part_(s,c)
#undef _Field_size_bytes_part_opt_
#define _Field_size_bytes_part_opt_(s,c)
#undef _Field_size_full_
#define _Field_size_full_(s)
#undef _Field_size_full_opt_
#define _Field_size_full_opt_(s)
#undef _Field_size_bytes_full_
#define _Field_size_bytes_full_(s)
#undef _Field_size_bytes_full_opt_
#define _Field_size_bytes_full_opt_(s)
#undef _Printf_format_string_
#define _Printf_format_string_
#undef _Scanf_format_string_
#define _Scanf_format_string_
#undef _Scanf_s_format_string_
#define _Scanf_s_format_string_
#undef _Printf_format_string_params_
#define _Printf_format_string_params_(x)
#undef _Scanf_format_string_params_
#define _Scanf_format_string_params_(x)
#undef _Scanf_s_format_string_params_
#define _Scanf_s_format_string_params_(x)
#undef _In_range_
#define _In_range_(l,h)
#undef _Out_range_
#define _Out_range_(l,h)
#undef _Ret_range_
#define _Ret_range_(l,h)
#undef _Deref_in_range_
#define _Deref_in_range_(l,h)
#undef _Deref_out_range_
#define _Deref_out_range_(l,h)
#undef _Deref_inout_range_
#define _Deref_inout_range_(l,h)
#undef _Field_range_
#define _Field_range_(l,h)
#undef _Pre_equal_to_
#define _Pre_equal_to_(e)
#undef _Post_equal_to_
#define _Post_equal_to_(e)
#undef _Struct_size_bytes_
#define _Struct_size_bytes_(s)
#undef _Analysis_assume_
#define _Analysis_assume_
#undef _Analysis_mode_
#define _Analysis_mode_(m)
#undef _Analysis_noreturn_
#define _Analysis_noreturn_
#undef _Raises_SEH_exception_
#define _Raises_SEH_exception_
#undef _Maybe_raises_SEH_exception_
#define _Maybe_raises_SEH_exception_
#undef _Function_class_
#define _Function_class_(n)
#undef _Literal_
#define _Literal_
#undef _Notliteral_
#define _Notliteral_
#undef _Enum_is_bitflag_
#define _Enum_is_bitflag_
#undef _Strict_type_match_
#define _Strict_type_match_
#undef _Points_to_data_
#define _Points_to_data_
#undef _Interlocked_operand_
#define _Interlocked_operand_
#undef _IRQL_raises_
#define _IRQL_raises_(i)
#undef _IRQL_requires_
#define _IRQL_requires_(i)
#undef _IRQL_requires_max_
#define _IRQL_requires_max_(i)
#undef _IRQL_requires_min_
#define _IRQL_requires_min_(i)
#undef _IRQL_saves_
#define _IRQL_saves_
#undef _IRQL_saves_global_
#define _IRQL_saves_global_(k,s)
#undef _IRQL_restores_
#define _IRQL_restores_
#undef _IRQL_restores_global_
#define _IRQL_restores_global_(k,s)
#undef _IRQL_always_function_min_
#define _IRQL_always_function_min_(i)
#undef _IRQL_always_function_max_
#define _IRQL_always_function_max_(i)
#undef _IRQL_requires_same_
#define _IRQL_requires_same_
#undef _IRQL_uses_cancel_
#define _IRQL_uses_cancel_
#undef _IRQL_is_cancel_
#define _IRQL_is_cancel_
#undef _Kernel_float_saved_
#define _Kernel_float_saved_
#undef _Kernel_float_restored_
#define _Kernel_float_restored_
#undef _Kernel_float_used_
#define _Kernel_float_used_
#undef _Kernel_acquires_resource_
#define _Kernel_acquires_resource_(k)
#undef _Kernel_releases_resource_
#define _Kernel_releases_resource_(k)
#undef _Kernel_requires_resource_held_
#define _Kernel_requires_resource_held_(k)
#undef _Kernel_requires_resource_not_held_
#define _Kernel_requires_resource_not_held_(k)
#undef _Kernel_clear_do_init_
#define _Kernel_clear_do_init_(yn)
#undef _Kernel_IoGetDmaAdapter_
#define _Kernel_IoGetDmaAdapter_
#undef _Outref_
#define _Outref_
#undef _Outref_result_maybenull_
#define _Outref_result_maybenull_
#undef _Outref_result_buffer_
#define _Outref_result_buffer_(s)
#undef _Outref_result_bytebuffer_
#define _Outref_result_bytebuffer_(s)
#undef _Outref_result_buffer_to_
#define _Outref_result_buffer_to_(s,c)
#undef _Outref_result_bytebuffer_to_
#define _Outref_result_bytebuffer_to_(s,c)
#undef _Outref_result_buffer_all_
#define _Outref_result_buffer_all_(s)
#undef _Outref_result_bytebuffer_all_
#define _Outref_result_bytebuffer_all_(s)
#undef _Outref_result_buffer_maybenull_
#define _Outref_result_buffer_maybenull_(s)
#undef _Outref_result_bytebuffer_maybenull_
#define _Outref_result_bytebuffer_maybenull_(s)
#undef _Outref_result_buffer_to_maybenull_
#define _Outref_result_buffer_to_maybenull_(s,c)
#undef _Outref_result_bytebuffer_to_maybenull_
#define _Outref_result_bytebuffer_to_maybenull_(s,c)
#undef _Outref_result_buffer_all_maybenull_
#define _Outref_result_buffer_all_maybenull_(s)
#undef _Outref_result_bytebuffer_all_maybenull_
#define _Outref_result_bytebuffer_all_maybenull_(s)
#undef _In_defensive_
#define _In_defensive_(a)
#undef _Out_defensive_
#define _Out_defensive_(a)
#undef _Inout_defensive_
#define _Inout_defensive_(a)
#undef _Outptr_result_nullonfailure_
#define _Outptr_result_nullonfailure_
#undef _Outptr_opt_result_nullonfailure_
#define _Outptr_opt_result_nullonfailure_
#undef _Outref_result_nullonfailure_
#define _Outref_result_nullonfailure_
#undef _Result_nullonfailure_
#define _Result_nullonfailure_
#undef _Result_zeroonfailure_
#define _Result_zeroonfailure_
#undef _Acquires_nonreentrant_lock_
#define _Acquires_nonreentrant_lock_(e)
#undef _Releases_nonreentrant_lock_
#define _Releases_nonreentrant_lock_(e)
#undef _Reserved_
#define _Reserved_           _Pre_equal_to_(0) _Pre_ _Null_
#undef _Pre_z_
#define _Pre_z_              _Pre_ _Null_terminated_
#undef _Post_z_
#define _Post_z_             _Post_ _Null_terminated_
#undef _Prepost_z_
#define _Prepost_z_          _Pre_z_ _Post_z_
#undef _Pre_null_
#define _Pre_null_           _Pre_ _Null_
#undef _Pre_maybenull_
#define _Pre_maybenull_      _Pre_ _Maybenull_
#undef _Pre_notnull_
#define _Pre_notnull_        _Pre_ _Notnull_
#undef _Pre_valid_
#define _Pre_valid_          _Pre_notnull_ _Pre_ _Valid_
#undef _Pre_opt_valid_
#define _Pre_opt_valid_      _Pre_maybenull_ _Pre_ _Valid_
#undef _Post_valid_
#define _Post_valid_         _Post_ _Valid_
#undef _Post_invalid_
#define _Post_invalid_       _Post_ _Deref_ _Notvalid_
#undef _Post_ptr_invalid_
#define _Post_ptr_invalid_   _Post_ _Notvalid_
#undef _Pre_readable_size_
#define _Pre_readable_size_(s)      _Pre_ _Readable_elements_(s) _Pre_ _Valid_
#undef _Pre_writable_size_
#define _Pre_writable_size_(s)      _Pre_ _Writable_elements_(s)
#undef _Pre_readable_byte_size_
#define _Pre_readable_byte_size_(s) _Pre_ _Readable_bytes_(s) _Pre_ _Valid_
#undef _Pre_writable_byte_size_
#define _Pre_writable_byte_size_(s) _Pre_ _Writable_bytes_(s)
#undef _Post_readable_size_
#define _Post_readable_size_(s)     _Post_ _Readable_elements_(s) _Post_ _Valid_
#undef _Post_writable_size_
#define _Post_writable_size_(s)     _Post_ _Writable_elements_(s)
#undef _Post_readable_byte_size_
#define _Post_readable_byte_size_(s) _Post_ _Readable_bytes_(s) _Post_ _Valid_
#undef _Post_writable_byte_size_
#define _Post_writable_byte_size_(s) _Post_ _Writable_bytes_(s)

#endif /* _NO_SAL_2_H_ */
