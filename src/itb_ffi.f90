! itb_ffi.f90 -- raw bind(C) interface declarations for the
! ITB_Triple_* surface of libitb.so, plus the introspection / runtime
! entry points the binding consumes, plus the C-string marshalling
! helpers shared by every higher-level module.
!
! Conventions (matching libitb.h):
!
!   * `int` (status, scalar)      -> integer(c_int)
!   * `size_t`                    -> integer(c_size_t)
!   * `int64_t`                   -> integer(c_int64_t)
!   * `uintptr_t` (opaque handle) -> integer(c_intptr_t)
!   * any pointer parameter       -> type(c_ptr), value; the wrapper
!     layer passes c_loc(buffer) (or c_null_ptr for empty buffers)
!   * output scalars (`size_t*`, `int*`, `uintptr_t*`) are declared
!     by-reference (no VALUE attribute) per C-interop semantics
!
! This module is internal plumbing: the public binding surface lives
! in itb_pipeline / itb_stream / itb_runtime / itb_opts / itb_error,
! re-exported by the root module itb.

module itb_ffi
  use, intrinsic :: iso_c_binding
  implicit none
  public

  interface

    ! ---- introspection + runtime knobs -----------------------------

    function c_itb_version(out, cap_bytes, out_len) &
        bind(C, name="ITB_Version") result(rc)
      import
      type(c_ptr), value       :: out
      integer(c_size_t), value :: cap_bytes
      integer(c_size_t)        :: out_len
      integer(c_int)           :: rc
    end function

    function c_itb_last_error(out, cap_bytes, out_len) &
        bind(C, name="ITB_LastError") result(rc)
      import
      type(c_ptr), value       :: out
      integer(c_size_t), value :: cap_bytes
      integer(c_size_t)        :: out_len
      integer(c_int)           :: rc
    end function

    function c_itb_hash_count() bind(C, name="ITB_HashCount") result(n)
      import
      integer(c_int) :: n
    end function

    function c_itb_hash_name(i, out, cap_bytes, out_len) &
        bind(C, name="ITB_HashName") result(rc)
      import
      integer(c_int), value    :: i
      type(c_ptr), value       :: out
      integer(c_size_t), value :: cap_bytes
      integer(c_size_t)        :: out_len
      integer(c_int)           :: rc
    end function

    function c_itb_hash_width(i) bind(C, name="ITB_HashWidth") result(w)
      import
      integer(c_int), value :: i
      integer(c_int)        :: w
    end function

    function c_itb_set_memory_limit(limit) &
        bind(C, name="ITB_SetMemoryLimit") result(prev)
      import
      integer(c_int64_t), value :: limit
      integer(c_int64_t)        :: prev
    end function

    function c_itb_set_gc_percent(pct) &
        bind(C, name="ITB_SetGCPercent") result(prev)
      import
      integer(c_int), value :: pct
      integer(c_int)        :: prev
    end function

    ! ---- Triple Pipeline lifecycle ---------------------------------

    function c_itb_triple_init(profile, opts, blob_out, blob_cap, &
        blob_len, out_handle) bind(C, name="ITB_Triple_Init") result(rc)
      import
      type(c_ptr), value       :: profile
      type(c_ptr), value       :: opts
      type(c_ptr), value       :: blob_out
      integer(c_size_t), value :: blob_cap
      integer(c_size_t)        :: blob_len
      integer(c_intptr_t)      :: out_handle
      integer(c_int)           :: rc
    end function

    function c_itb_triple_open(profile, blob, blob_len, opts, &
        perm_master, perm_master_len, wrap_master, wrap_master_len, &
        masters_count, out_handle) bind(C, name="ITB_Triple_Open") result(rc)
      import
      type(c_ptr), value       :: profile
      type(c_ptr), value       :: blob
      integer(c_size_t), value :: blob_len
      type(c_ptr), value       :: opts
      type(c_ptr), value       :: perm_master
      integer(c_size_t), value :: perm_master_len
      type(c_ptr), value       :: wrap_master
      integer(c_size_t), value :: wrap_master_len
      integer(c_size_t), value :: masters_count
      integer(c_intptr_t)      :: out_handle
      integer(c_int)           :: rc
    end function

    function c_itb_triple_rekey(handle, perm_master, perm_master_len, &
        wrap_master, wrap_master_len, blob_out, blob_cap, blob_len) &
        bind(C, name="ITB_Triple_Rekey") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: perm_master
      integer(c_size_t), value   :: perm_master_len
      type(c_ptr), value         :: wrap_master
      integer(c_size_t), value   :: wrap_master_len
      type(c_ptr), value         :: blob_out
      integer(c_size_t), value   :: blob_cap
      integer(c_size_t)          :: blob_len
      integer(c_int)             :: rc
    end function

    function c_itb_triple_close(handle) &
        bind(C, name="ITB_Triple_Close") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: rc
    end function

    function c_itb_triple_free(handle) &
        bind(C, name="ITB_Triple_Free") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: rc
    end function

    function c_itb_triple_register_profile(name, opts) &
        bind(C, name="ITB_Triple_RegisterProfile") result(rc)
      import
      type(c_ptr), value :: name
      type(c_ptr), value :: opts
      integer(c_int)     :: rc
    end function

    ! ---- Triple Pipeline cipher paths ------------------------------

    function c_itb_triple_encrypt_stream(handle, src, src_len, out, &
        out_cap, out_len) bind(C, name="ITB_Triple_EncryptStream") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: src
      integer(c_size_t), value   :: src_len
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: out_cap
      integer(c_size_t)          :: out_len
      integer(c_int)             :: rc
    end function

    function c_itb_triple_decrypt_stream(handle, src, src_len, out, &
        out_cap, out_len) bind(C, name="ITB_Triple_DecryptStream") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: src
      integer(c_size_t), value   :: src_len
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: out_cap
      integer(c_size_t)          :: out_len
      integer(c_int)             :: rc
    end function

    function c_itb_triple_encrypt_message(handle, src, src_len, out, &
        out_cap, out_len) bind(C, name="ITB_Triple_EncryptMessage") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: src
      integer(c_size_t), value   :: src_len
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: out_cap
      integer(c_size_t)          :: out_len
      integer(c_int)             :: rc
    end function

    function c_itb_triple_decrypt_message(handle, src, src_len, out, &
        out_cap, out_len) bind(C, name="ITB_Triple_DecryptMessage") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: src
      integer(c_size_t), value   :: src_len
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: out_cap
      integer(c_size_t)          :: out_len
      integer(c_int)             :: rc
    end function

    ! ---- incremental stream sessions -------------------------------

    function c_itb_triple_encrypt_stream_begin(pipe, out_stream) &
        bind(C, name="ITB_Triple_EncryptStreamBegin") result(rc)
      import
      integer(c_intptr_t), value :: pipe
      integer(c_intptr_t)        :: out_stream
      integer(c_int)             :: rc
    end function

    function c_itb_triple_decrypt_stream_begin(pipe, out_stream) &
        bind(C, name="ITB_Triple_DecryptStreamBegin") result(rc)
      import
      integer(c_intptr_t), value :: pipe
      integer(c_intptr_t)        :: out_stream
      integer(c_int)             :: rc
    end function

    function c_itb_triple_stream_write(stream, src, src_len) &
        bind(C, name="ITB_Triple_StreamWrite") result(rc)
      import
      integer(c_intptr_t), value :: stream
      type(c_ptr), value         :: src
      integer(c_size_t), value   :: src_len
      integer(c_int)             :: rc
    end function

    function c_itb_triple_stream_end(stream) &
        bind(C, name="ITB_Triple_StreamEnd") result(rc)
      import
      integer(c_intptr_t), value :: stream
      integer(c_int)             :: rc
    end function

    function c_itb_triple_stream_read(stream, out, out_cap, out_len, &
        finished) bind(C, name="ITB_Triple_StreamRead") result(rc)
      import
      integer(c_intptr_t), value :: stream
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: out_cap
      integer(c_size_t)          :: out_len
      integer(c_int)             :: finished
      integer(c_int)             :: rc
    end function

    function c_itb_triple_stream_free(stream) &
        bind(C, name="ITB_Triple_StreamFree") result(rc)
      import
      integer(c_intptr_t), value :: stream
      integer(c_int)             :: rc
    end function

  end interface

contains

  ! Build a NUL-terminated c_char array from a Fortran string. Bytes
  ! 1..len(s) carry the source characters, byte len(s)+1 is the NUL.
  ! An empty source maps to a one-byte buffer holding only the
  ! terminator, keeping c_loc(buf) valid (libitb treats an empty
  ! string and NULL alike on every string parameter it accepts).
  subroutine itb_to_cstr(s, buf)
    character(*), intent(in)                                 :: s
    character(kind=c_char), allocatable, target, intent(out) :: buf(:)
    integer :: i, n

    n = len(s)
    allocate (buf(n + 1))
    do i = 1, n
      buf(i) = s(i:i)
    end do
    buf(n + 1) = c_null_char
  end subroutine

  ! Convert a libitb-output (buf, len) pair to a Fortran allocatable
  ! string. libitb reports out_len INCLUDING the trailing NUL; the
  ! NUL is stripped here.
  subroutine itb_from_cstr(buf, n_bytes, s)
    character(kind=c_char), intent(in)     :: buf(*)
    integer(c_size_t), intent(in)          :: n_bytes
    character(:), allocatable, intent(out) :: s
    integer :: visible, i

    visible = int(n_bytes)
    if (visible < 0) visible = 0
    if (visible > 0) then
      if (buf(visible) == c_null_char) visible = visible - 1
    end if
    allocate (character(len=visible) :: s)
    do i = 1, visible
      s(i:i) = buf(i)
    end do
  end subroutine

end module itb_ffi
