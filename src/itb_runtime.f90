! itb_runtime.f90 -- process-wide Go runtime knobs, the library
! version string, and the hash-registry accessors.

module itb_runtime
  use, intrinsic :: iso_c_binding, only: c_int, c_int64_t, c_size_t, &
      c_char, c_loc
  use itb_status
  use itb_ffi
  use itb_error
  implicit none
  private

  public :: itb_set_memory_limit, itb_set_gc_percent, itb_version, &
            itb_hash_count, itb_hash_name, itb_hash_width

  ! Binding release; printed by `eitb version` next to the libitb
  ! version reported by ITB_Version.
  character(*), parameter, public :: ITB_BINDING_VERSION = "0.3.0"

contains

  ! Sets the Go runtime's soft heap limit in bytes and returns the
  ! previous limit. A negative value queries without changing.
  function itb_set_memory_limit(limit_bytes) result(prev)
    integer(c_int64_t), intent(in) :: limit_bytes
    integer(c_int64_t)             :: prev
    prev = c_itb_set_memory_limit(limit_bytes)
  end function

  ! Sets the Go GC trigger percentage and returns the previous value.
  ! A negative value queries without changing.
  function itb_set_gc_percent(pct) result(prev)
    integer(c_int), intent(in) :: pct
    integer(c_int)             :: prev
    prev = c_itb_set_gc_percent(pct)
  end function

  ! The libitb library version string.
  subroutine itb_version(version, err)
    character(:), allocatable, intent(out) :: version
    type(itb_error_t), intent(out)         :: err
    character(kind=c_char), target :: buf(128)
    integer(c_size_t) :: n
    integer(c_int)    :: rc

    version = ""
    n = 0_c_size_t
    rc = c_itb_version(c_loc(buf(1)), int(size(buf), c_size_t), n)
    call itb_error_set(err, rc)
    if (.not. itb_ok(err)) return
    call itb_from_cstr(buf, n, version)
  end subroutine

  ! Number of shipped hash primitives.
  function itb_hash_count() result(n)
    integer(c_int) :: n
    n = c_itb_hash_count()
  end function

  ! Canonical name of the i-th hash primitive (0-based index).
  subroutine itb_hash_name(i, name, err)
    integer(c_int), intent(in)             :: i
    character(:), allocatable, intent(out) :: name
    type(itb_error_t), intent(out)         :: err
    character(kind=c_char), target :: buf(128)
    integer(c_size_t) :: n
    integer(c_int)    :: rc

    name = ""
    n = 0_c_size_t
    rc = c_itb_hash_name(i, c_loc(buf(1)), int(size(buf), c_size_t), n)
    call itb_error_set(err, rc)
    if (.not. itb_ok(err)) return
    call itb_from_cstr(buf, n, name)
  end subroutine

  ! Native intermediate-state width of the i-th hash primitive, or 0
  ! when i is out of range.
  function itb_hash_width(i) result(w)
    integer(c_int), intent(in) :: i
    integer(c_int)             :: w
    w = c_itb_hash_width(i)
  end function

end module itb_runtime
