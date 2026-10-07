! Process-wide Go runtime knobs and the library version string.

module itb_runtime
  use, intrinsic :: iso_c_binding, only: c_int, c_int64_t, c_size_t, &
      c_char, c_loc
  use itb_status
  use itb_ffi
  use itb_error
  implicit none
  private

  public :: itb_set_memory_limit, itb_set_gc_percent, itb_version
  public :: itb_drbg_auto_tier
  public :: itb_set_gomaxprocs, itb_write_heap_profile
  public :: itb_pool_stats_len, itb_pool_stats

  ! Binding release; printed by `eitb version` next to the libitb3
  ! version reported by ITB_Version.
  character(*), parameter, public :: ITB_BINDING_VERSION = "0.5.1"

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

  ! The libitb3 library version string.
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

  ! The fill cipher the auto DRBG tier selected on this host
  ! ("aes-256-ctr" or "chacha20"): the tier a Pipeline uses when its
  ! drbg option is empty, resolved per host and recorded in no blob.
  subroutine itb_drbg_auto_tier(tier, err)
    character(:), allocatable, intent(out) :: tier
    type(itb_error_t), intent(out)         :: err
    character(kind=c_char), target :: buf(64)
    integer(c_size_t) :: n
    integer(c_int)    :: rc

    tier = ""
    n = 0_c_size_t
    rc = c_itb_drbg_auto_tier(c_loc(buf(1)), int(size(buf), c_size_t), n)
    call itb_error_set(err, rc)
    if (.not. itb_ok(err)) return
    call itb_from_cstr(buf, n, tier)
  end subroutine

  ! Sets the Go runtime's GOMAXPROCS and returns the previous value.
  ! Zero or a negative value queries without changing. Readable at
  ! libitb3 load time via ITB_GOMAXPROCS; this setter overrides it.
  function itb_set_gomaxprocs(n) result(prev)
    integer(c_int), intent(in) :: n
    integer(c_int)             :: prev
    prev = c_itb_set_gomaxprocs(n)
  end function

  ! Writes a Go runtime heap profile (pprof format) to path after one
  ! forced collection. An empty path falls back to the ITB_MEMPROFILE
  ! environment variable; a path that is still empty, or a
  ! file-system failure, is ITB_STATUS_BAD_INPUT with the diagnostic
  ! in err%message.
  subroutine itb_write_heap_profile(path, err)
    character(*), intent(in)       :: path
    type(itb_error_t), intent(out) :: err
    character(kind=c_char), allocatable, target :: c_path(:)

    call itb_to_cstr(path, c_path)
    call itb_error_set(err, c_itb_write_heap_profile(c_loc(c_path(1))))
  end subroutine

  ! Number of counter slots itb_pool_stats fills. A destination is
  ! sized from this call, never from a constant: the slot layout grows
  ! with the hash-array pool's tier count, which slot 1 carries.
  function itb_pool_stats_len() result(n)
    integer :: n
    integer(c_int) :: raw
    raw = c_itb_pool_stats_len()
    n = 0
    if (raw > 0) n = int(raw)
  end function

  ! Copies the libitb3 cipher core's pool hit / miss counters into dst
  ! and reports how many slots were written. Every counter is a
  ! monotonically increasing total since library load, so a caller
  ! differences two snapshots.
  !
  ! Slot layout, with T the tier count in dst(1): tier i holds starter
  ! width, checkouts, constructor misses, regrow replacements and
  ! bytes allocated at the five slots from 2 + 5*i; the scratch byte
  ! pool's get / new / regrow / regrow-bytes follow at 2 + 5*T, and
  ! the parallax chunk pool's at 6 + 5*T. A dst shorter than
  ! itb_pool_stats_len is ITB_STATUS_BUFFER_TOO_SMALL, with the
  ! requirement reported through n_written.
  subroutine itb_pool_stats(dst, n_written, err)
    integer(c_int64_t), intent(out), target, contiguous :: dst(:)
    integer, intent(out)                                :: n_written
    type(itb_error_t), intent(out)                      :: err
    integer(c_size_t) :: written
    integer(c_int)    :: rc

    dst = 0_c_int64_t
    written = 0_c_size_t
    if (size(dst) > 0) then
      rc = c_itb_pool_stats(c_loc(dst(1)), int(size(dst), c_size_t), written)
    else
      ! An empty destination has no first element to take the address
      ! of, so the probe form goes over as a null pointer with
      ! capacity zero; libitb3 then reports the requirement through
      ! written without writing anywhere.
      rc = c_itb_pool_stats(c_null_ptr, 0_c_size_t, written)
    end if
    n_written = int(written)
    call itb_error_set(err, rc)
  end subroutine

end module itb_runtime
