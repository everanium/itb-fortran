! itb.f90 -- root module of the ITB Fortran binding: a thin proxy over
! the libitb shared library's Triple Pipeline surface (ITB_Triple_*).
!
! `use itb` re-exports the whole public surface:
!
!   * itb_pipeline_t + init / load / load_f / save / save_f / rekey /
!     max_workers / close / free
!   * Single Message encrypt / decrypt, one-shot stream encrypt /
!     decrypt, whole-buffer stream pumps
!   * itb_stream_t incremental sessions (begin / write / end / read /
!     drain_all / free)
!   * itb_opts_t URL-query builder for init overrides
!   * profile records: itb_inspect / itb_register / itb_lookup /
!     itb_profiles (JSON strings)
!   * itb_error_t + status constants + labels
!   * Go runtime knobs, library version, hash-registry accessors
!
! Every hash-name / MAC-name / cipher-name / profile-name is an
! opaque character(*) passed through to Go for validation; the
! binding carries no ITB construction logic of its own.
!
! Bytes cross the surface as integer(c_int8_t) arrays; the interop
! kinds the surface uses (c_int8_t, c_int, c_int64_t, c_intptr_t)
! are re-exported here so callers need no separate iso_c_binding use.

module itb
  use, intrinsic :: iso_c_binding, only: c_int8_t, c_int, c_int64_t, &
      c_intptr_t
  use itb_status
  use itb_error
  use itb_opts
  use itb_runtime
  use itb_pipeline
  use itb_stream
  implicit none
  public
end module itb
