! itb_kinds.f90 -- public KIND aliases re-exported from iso_c_binding.
!
! The binding's higher-level modules import KINDs from here rather than
! directly from `iso_c_binding`. This gives a single canonical set of
! type names for the binding surface and lets future ports retarget
! without sweeping every source file (e.g. a hypothetical 32-bit build
! could remap `itb_handle_kind` without touching the call sites).
!
! There are no runtime symbols in this module -- it is type-only.

module itb_kinds
  use, intrinsic :: iso_c_binding, only:                       &
        c_int, c_int8_t, c_int32_t, c_int64_t,                 &
        c_size_t, c_intptr_t, c_char, c_null_char,             &
        c_ptr, c_funptr, c_null_ptr, c_null_funptr,            &
        c_loc, c_funloc, c_f_pointer, c_associated
  implicit none
  public

  ! Status / fixed-int return codes. Every libitb FFI entry point
  ! returns `int`; bindings receive a kind-c_int.
  integer, parameter :: itb_status_kind = c_int

  ! Opaque handle kind. libitb exposes handles as `uintptr_t` in the
  ! C-ABI header; iso_c_binding's `c_intptr_t` is the matching Fortran
  ! kind and is guaranteed equal-width with the host pointer.
  integer, parameter :: itb_handle_kind = c_intptr_t

  ! Byte-buffer kind for `uint8_t *` parameters (cipher I/O, MAC keys,
  ! BLOB payloads, hash keys).
  integer, parameter :: itb_byte_kind = c_int8_t

  ! Component kind for the 8..32 uint64 seed components and the BLOB
  ! component arrays.
  integer, parameter :: itb_u64_kind = c_int64_t

  ! Size kind for `size_t` parameters and `*outLen` output capacities.
  integer, parameter :: itb_size_kind = c_size_t

  ! 32-bit signed counter kind (e.g. seed-component count from
  ! `ITB_GetSeedComponents`, slot indexes for Mixed encryptors).
  integer, parameter :: itb_int32_kind = c_int32_t

  ! Sentinel zero handle (`(uintptr_t)0`) -- libitb's "null handle"
  ! convention. Used by the wrapper layer to detect closed / freed
  ! state without round-tripping libitb.
  integer(itb_handle_kind), parameter :: itb_null_handle = 0_c_intptr_t

end module itb_kinds
