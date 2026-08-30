! itb_stream.f90 -- incremental stream sessions over an open Pipeline.
!
! A session is a dumb byte pump: an encrypt session takes plaintext
! in through itb_stream_write and yields wire through itb_stream_read
! / itb_stream_drain_all; a decrypt session is the mirror (wire in,
! plaintext out). All chunking, MAC, envelope, and wire-format
! decisions stay inside libitb.
!
! Lifetime discipline: every successful itb_encrypt_stream_begin /
! itb_decrypt_stream_begin must be paired with exactly one
! itb_stream_free call, which cancels (if still running) and releases
! the session from any state. A session must not outlive its parent
! Pipeline.
!
! The whole-buffer pumps (itb_encrypt_stream_pump /
! itb_decrypt_stream_pump) feed 1 MiB slices and drain between
! writes so the Go-side spool stays bounded.

module itb_stream
  use, intrinsic :: iso_c_binding, only: c_int, c_int8_t, c_size_t, &
      c_intptr_t, c_ptr, c_loc, c_null_ptr
  use, intrinsic :: iso_fortran_env, only: int64
  use itb_status
  use itb_ffi
  use itb_error
  use itb_pipeline
  implicit none
  private

  public :: itb_stream_t
  public :: itb_encrypt_stream_begin, itb_decrypt_stream_begin
  public :: itb_stream_write, itb_stream_end, itb_stream_read
  public :: itb_stream_drain_all, itb_stream_free
  public :: itb_encrypt_stream_pump, itb_decrypt_stream_pump
  public :: itb_encrypt_stream_pump_into, itb_decrypt_stream_pump_into

  type :: itb_stream_t
    integer(c_intptr_t) :: handle = 0_c_intptr_t
    logical             :: ended = .false.
  end type

  ! Feed / drain slice size used by the pump loops.
  integer, parameter :: PUMP_BUF = 2**20

  ! The pump bound arithmetic (used / cap / size) is default integer;
  ! inputs above this 1.5 GiB ceiling are rejected up front so the
  ! sizing bound PUMP_MAX_SRC + PUMP_MAX_SRC / 4 + 131072 (and the
  ! used / cap counters downstream) can never wrap. Larger payloads
  ! go through the incremental sessions.
  integer, parameter :: PUMP_MAX_SRC = 3 * 2**29

contains

  ! Opens an incremental encrypt session (plaintext in, wire out).
  subroutine itb_encrypt_stream_begin(pipe, sess, err)
    type(itb_pipeline_t), intent(in) :: pipe
    type(itb_stream_t), intent(out)  :: sess
    type(itb_error_t), intent(out)   :: err
    integer(c_intptr_t) :: handle

    call itb_error_set(err, &
        c_itb_triple_encrypt_stream_begin(pipe%handle, handle))
    if (itb_ok(err)) sess%handle = handle
  end subroutine

  ! Opens an incremental decrypt session (wire in, plaintext out).
  subroutine itb_decrypt_stream_begin(pipe, sess, err)
    type(itb_pipeline_t), intent(in) :: pipe
    type(itb_stream_t), intent(out)  :: sess
    type(itb_error_t), intent(out)   :: err
    integer(c_intptr_t) :: handle

    call itb_error_set(err, &
        c_itb_triple_decrypt_stream_begin(pipe%handle, handle))
    if (itb_ok(err)) sess%handle = handle
  end subroutine

  ! Feeds src into the session. Blocks until the cipher chain accepts
  ! the bytes; errors are sticky. A zero-length src is a no-op.
  subroutine itb_stream_write(sess, src, err)
    type(itb_stream_t), intent(inout)                 :: sess
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    type(itb_error_t), intent(out)                    :: err
    type(c_ptr) :: src_p

    src_p = c_null_ptr
    if (size(src) > 0) src_p = c_loc(src(1))
    call itb_error_set(err, c_itb_triple_stream_write(sess%handle, &
        src_p, size(src, kind=c_size_t)))
  end subroutine

  ! Signals end-of-input. Idempotent; itb_stream_write after end
  ! fails with ITB_STATUS_BAD_INPUT.
  subroutine itb_stream_end(sess, err)
    type(itb_stream_t), intent(inout) :: sess
    type(itb_error_t), intent(out)    :: err

    call itb_error_set(err, c_itb_triple_stream_end(sess%handle))
    if (itb_ok(err)) sess%ended = .true.
  end subroutine

  ! Drains up to size(buf) produced bytes into buf(1:n_read).
  ! finished becomes .true. once the session has ended AND the spool
  ! is fully drained. Partial drains are normal. Before end, an
  ! empty-spool read returns n_read = 0 without blocking; after end
  ! it blocks until the terminal bytes arrive or the session errors.
  subroutine itb_stream_read(sess, buf, n_read, finished, err)
    type(itb_stream_t), intent(inout)                    :: sess
    integer(c_int8_t), intent(inout), target, contiguous :: buf(:)
    integer, intent(out)                                 :: n_read
    logical, intent(out)                                 :: finished
    type(itb_error_t), intent(out)                       :: err
    integer(c_size_t) :: out_len
    integer(c_int)    :: fin

    n_read = 0
    finished = .false.
    out_len = 0_c_size_t
    fin = 0
    call itb_error_set(err, c_itb_triple_stream_read(sess%handle, &
        c_loc(buf(1)), size(buf, kind=c_size_t), out_len, fin))
    if (.not. itb_ok(err)) return
    n_read = int(out_len)
    finished = (fin /= 0)
  end subroutine

  ! Calls end (if not yet called) and appends every remaining output
  ! byte to dst (allocated / grown as needed).
  subroutine itb_stream_drain_all(sess, dst, err)
    type(itb_stream_t), intent(inout)             :: sess
    integer(c_int8_t), allocatable, intent(inout) :: dst(:)
    type(itb_error_t), intent(out)                :: err
    integer(c_int8_t), allocatable, target :: buf(:)
    integer :: n, used
    logical :: fin

    allocate (buf(PUMP_BUF))
    if (.not. allocated(dst)) allocate (dst(0))
    if (.not. sess%ended) then
      call itb_stream_end(sess, err)
      if (.not. itb_ok(err)) return
    end if
    used = size(dst)
    do
      call itb_stream_read(sess, buf, n, fin, err)
      if (.not. itb_ok(err)) return
      call append_bytes(dst, used, buf, n)
      if (fin) exit
    end do
    call trim_bytes(dst, used)
  end subroutine

  ! Cancels (if still running) and releases the session. Safe from
  ! any state; the status of the underlying free is deliberately
  ! discarded on this destructor path.
  subroutine itb_stream_free(sess)
    type(itb_stream_t), intent(inout) :: sess
    integer(c_int) :: rc

    if (sess%handle /= 0_c_intptr_t) then
      rc = c_itb_triple_stream_free(sess%handle)
      if (rc /= ITB_STATUS_OK) continue
    end if
    sess%handle = 0_c_intptr_t
    sess%ended = .false.
  end subroutine

  ! Pumps src through an encrypt session into dst with bounded
  ! Go-side spooling: feed a 1 MiB slice, drain available wire,
  ! repeat; end + final drain after the last slice. The session is
  ! freed on return (success or failure).
  subroutine itb_encrypt_stream_pump(pipe, src, dst, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    integer(c_int8_t), allocatable, intent(out)       :: dst(:)
    type(itb_error_t), intent(out)                    :: err

    call pump(pipe, .true., src, dst, err)
  end subroutine

  ! Receive-side counterpart of itb_encrypt_stream_pump.
  subroutine itb_decrypt_stream_pump(pipe, src, dst, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    integer(c_int8_t), allocatable, intent(out)       :: dst(:)
    type(itb_error_t), intent(out)                    :: err

    call pump(pipe, .false., src, dst, err)
  end subroutine

  ! Reusable-buffer pump: dst is caller-owned scratch, grown once to
  ! the wire-expansion bound and reused verbatim across calls;
  ! dst(1:n_out) holds the produced bytes on success (no trim, no
  ! exact-size copy). The drain reads land directly in dst via
  ! c_loc on the tail slice -- zero intermediate copies.
  ! The src and dst arrays must not overlap; in-place operation is
  ! not supported. Bytes beyond n_out are undefined and may hold
  ! prior-call material; the caller must not read them. After a
  ! failed call the contents of dst are unspecified.
  ! Inputs larger than PUMP_MAX_SRC are rejected with
  ! ITB_STATUS_BAD_INPUT; use the incremental sessions instead.
  subroutine itb_encrypt_stream_pump_into(pipe, src, dst, n_out, err)
    type(itb_pipeline_t), intent(in)                      :: pipe
    integer(c_int8_t), intent(in), target, contiguous     :: src(:)
    integer(c_int8_t), allocatable, intent(inout), target :: dst(:)
    integer(c_size_t), intent(out)                        :: n_out
    type(itb_error_t), intent(out)                        :: err
    integer :: used

    call pump_into(pipe, .true., src, dst, used, err)
    n_out = int(used, c_size_t)
  end subroutine

  ! Receive-side counterpart of itb_encrypt_stream_pump_into (same
  ! buffer contract: src and dst must not overlap; bytes beyond
  ! n_out are undefined; after a failed call the contents of dst
  ! are unspecified and must not be interpreted).
  subroutine itb_decrypt_stream_pump_into(pipe, src, dst, n_out, err)
    type(itb_pipeline_t), intent(in)                      :: pipe
    integer(c_int8_t), intent(in), target, contiguous     :: src(:)
    integer(c_int8_t), allocatable, intent(inout), target :: dst(:)
    integer(c_size_t), intent(out)                        :: n_out
    type(itb_error_t), intent(out)                        :: err
    integer :: used

    call pump_into(pipe, .false., src, dst, used, err)
    n_out = int(used, c_size_t)
  end subroutine

  ! Exact-size wrapper over pump_into: one scratch pump, then a
  ! single exact-length copy into the callee-allocated dst.
  subroutine pump(pipe, encrypt, src, dst, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    logical, intent(in)                               :: encrypt
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    integer(c_int8_t), allocatable, intent(out)       :: dst(:)
    type(itb_error_t), intent(out)                    :: err
    integer(c_int8_t), allocatable, target :: buf(:)
    integer :: used

    call pump_into(pipe, encrypt, src, buf, used, err)
    if (.not. itb_ok(err)) return
    dst = buf(1:used)
  end subroutine

  ! Shared body for the whole-buffer pumps. dst is sized up front to
  ! the wire-expansion upper bound (the same bound the Single Message
  ! path uses), so the drain loop appends in place with no growth
  ! copies on the hot path; ensure_room is a never-in-practice
  ! fallback should libitb outproduce the bound.
  subroutine pump_into(pipe, encrypt, src, dst, used, err)
    type(itb_pipeline_t), intent(in)                      :: pipe
    logical, intent(in)                                   :: encrypt
    integer(c_int8_t), intent(in), target, contiguous     :: src(:)
    integer(c_int8_t), allocatable, intent(inout), target :: dst(:)
    integer, intent(out)                                  :: used
    type(itb_error_t), intent(out)                        :: err
    type(itb_stream_t) :: sess
    integer :: lo, hi, n, cap
    logical :: fin

    used = 0
    ! Reject inputs whose default-integer bound arithmetic below (and
    ! the used / cap counters downstream) could wrap; every size on
    ! the pump path is then provably inside the 32-bit bound.
    if (size(src, kind=c_size_t) > int(PUMP_MAX_SRC, c_size_t)) then
      err%status = ITB_STATUS_BAD_INPUT
      err%message = "stream pump input exceeds the whole-buffer bound; "// &
          "use the incremental stream sessions"
      return
    end if
    cap = max(131072, size(src) + size(src) / 4 + 131072)
    if (.not. allocated(dst)) then
      allocate (dst(cap))
    else if (size(dst) < cap) then
      deallocate (dst)
      allocate (dst(cap))
    end if

    if (encrypt) then
      call itb_encrypt_stream_begin(pipe, sess, err)
    else
      call itb_decrypt_stream_begin(pipe, sess, err)
    end if
    if (.not. itb_ok(err)) return

    lo = 1
    do while (lo <= size(src))
      hi = min(lo + PUMP_BUF - 1, size(src))
      call itb_stream_write(sess, src(lo:hi), err)
      if (.not. itb_ok(err)) then
        call itb_stream_free(sess)
        return
      end if
      lo = hi + 1
      ! Drain whatever the chain has produced so far straight into
      ! dst's free tail; a read before end never blocks.
      do
        call ensure_room(dst, used)
        call itb_stream_read(sess, dst(used + 1:), n, fin, err)
        ! Bounds sanity on the FFI-reported drain length; an
        ! out-of-range n would corrupt the next ensure_room copy.
        if (itb_ok(err) .and. (n < 0 .or. n > size(dst) - used)) &
            call itb_error_set(err, ITB_STATUS_INTERNAL)
        if (.not. itb_ok(err)) then
          call itb_stream_free(sess)
          return
        end if
        if (n == 0) exit
        used = used + n
      end do
    end do

    call itb_stream_end(sess, err)
    if (.not. itb_ok(err)) then
      call itb_stream_free(sess)
      return
    end if
    do
      call ensure_room(dst, used)
      call itb_stream_read(sess, dst(used + 1:), n, fin, err)
      ! Bounds sanity on the FFI-reported drain length; an
      ! out-of-range n would corrupt the next ensure_room copy.
      if (itb_ok(err) .and. (n < 0 .or. n > size(dst) - used)) &
          call itb_error_set(err, ITB_STATUS_INTERNAL)
      if (.not. itb_ok(err)) then
        call itb_stream_free(sess)
        return
      end if
      used = used + n
      if (fin) exit
    end do
    call itb_stream_free(sess)
  end subroutine

  ! Guarantees at least 64 KiB of free tail in dst so the drain slice
  ! dst(used+1:) is never zero-sized. On the hot path the up-front
  ! wire-expansion bound already covers the whole run and this is a
  ! branch-not-taken; the growth arm exists only as a safety valve.
  subroutine ensure_room(dst, used)
    integer(c_int8_t), allocatable, intent(inout), target :: dst(:)
    integer, intent(in)                                   :: used
    integer(c_int8_t), allocatable :: grown(:)
    integer :: cap
    integer(int64) :: cap64

    if (size(dst) - used >= 65536) return
    ! Growth arithmetic in 64-bit so the sizing can never wrap; the
    ! pump input guard keeps every reachable size inside the 32-bit
    ! bound, so the trap below is a safety valve, not a code path.
    cap64 = max(int(size(dst), int64) * 3_int64 / 2_int64, &
        int(used, int64) + int(PUMP_BUF, int64))
    if (cap64 > int(huge(0), int64)) &
        error stop "itb_stream: pump buffer exceeds the 32-bit bound"
    cap = int(cap64)
    allocate (grown(cap))
    if (used > 0) grown(1:used) = dst(1:used)
    call move_alloc(grown, dst)
  end subroutine

  ! Amortised append: dst holds `used` valid bytes and grows by
  ! doubling; the caller trims to the exact length at the end via
  ! trim_bytes.
  subroutine append_bytes(dst, used, src, n)
    integer(c_int8_t), allocatable, intent(inout) :: dst(:)
    integer, intent(inout)                        :: used
    integer(c_int8_t), intent(in)                 :: src(:)
    integer, intent(in)                           :: n
    integer(c_int8_t), allocatable :: grown(:)
    integer :: cap

    if (n <= 0) return
    cap = size(dst)
    if (used + n > cap) then
      cap = max(cap * 2, used + n, 65536)
      allocate (grown(cap))
      if (used > 0) grown(1:used) = dst(1:used)
      call move_alloc(grown, dst)
    end if
    dst(used + 1:used + n) = src(1:n)
    used = used + n
  end subroutine

  subroutine trim_bytes(dst, used)
    integer(c_int8_t), allocatable, intent(inout) :: dst(:)
    integer, intent(in)                           :: used
    integer(c_int8_t), allocatable :: exact(:)

    if (size(dst) == used) return
    allocate (exact(used))
    if (used > 0) exact(1:used) = dst(1:used)
    call move_alloc(exact, dst)
  end subroutine

end module itb_stream
