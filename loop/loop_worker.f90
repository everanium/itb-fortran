! The worker: its thread body (one warmup iteration, the warmup
! barrier, the main loop), one iteration, the session pump loop the
! stream shape drives, and the round-trip comparison that decides
! between a worker error and a data mismatch.

module loop_worker
  use, intrinsic :: iso_c_binding
  use itb3
  use loop_size, only: itoa, now_ns
  use loop_state
  use loop_payload, only: fill_payload
  use loop_ops, only: worker_maintenance
  implicit none
  private

  public :: shape_name, parse_shape, worker_warmup, worker_loop

  character(len=15), parameter :: SHAPE_NAMES(0:3) = [ &
      "stream         ", "message        ", &
      "stream_one_shot", "both           "]

contains

  function shape_name(shape) result(s)
    integer, intent(in)       :: shape
    character(:), allocatable :: s
    s = trim(SHAPE_NAMES(shape))
  end function

  function parse_shape(text, shape) result(ok)
    character(*), intent(in) :: text
    integer, intent(out)     :: shape
    logical                  :: ok
    integer :: i

    shape = SHAPE_STREAM
    ok = .false.
    do i = 0, 3
      if (text == trim(SHAPE_NAMES(i))) then
        shape = i
        ok = .true.
        return
      end if
    end do
  end function

  ! Appends n bytes of src to the accumulator, growing it by doubling
  ! so the steady-state allocation profile of the pump loop stays
  ! flat across iterations.
  subroutine accumulate(dst, used, src, n)
    integer(c_int8_t), allocatable, intent(inout) :: dst(:)
    integer(c_int64_t), intent(inout)             :: used
    integer(c_int8_t), intent(in)                 :: src(:)
    integer, intent(in)                           :: n
    integer(c_int8_t), allocatable :: grown(:)
    integer(c_int64_t) :: cap

    if (n <= 0) return
    if (.not. allocated(dst)) allocate (dst(PUMP_SLICE))
    cap = int(size(dst, kind=c_int64_t), c_int64_t)
    if (used + int(n, c_int64_t) > cap) then
      do while (cap < used + int(n, c_int64_t))
        cap = cap * 2_c_int64_t
      end do
      allocate (grown(cap))
      if (used > 0_c_int64_t) grown(1:used) = dst(1:used)
      call move_alloc(grown, dst)
    end if
    dst(used + 1_c_int64_t:used + int(n, c_int64_t)) = src(1:n)
    used = used + int(n, c_int64_t)
  end subroutine

  ! Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
  ! and ITB drives the chunk loop internally; the C ABI has no reader
  ! / writer entry, so the caller drives it: open a session, feed
  ! slices of at most 1 MiB, drain whatever the session has produced
  ! after every write (a read before end never blocks), end, then
  ! drain until the session reports finished (after end, a read on an
  ! empty spool blocks until the terminal bytes arrive). The whole
  ! produced output lands in the worker's reusable accumulator. The
  ! loop is written here rather than delegated to the binding's pump
  ! convenience so it stands in the utility, at the same place, in
  ! every language.
  function pump(pipe, encrypt, src, src_len, dst, dst_len, what, err) &
      result(ok)
    type(itb_pipeline_t), intent(in)                   :: pipe
    logical, intent(in)                                :: encrypt
    integer(c_int8_t), intent(in), target, contiguous  :: src(:)
    integer(c_int64_t), intent(in)                     :: src_len
    integer(c_int8_t), allocatable, intent(inout)      :: dst(:)
    integer(c_int64_t), intent(out)                    :: dst_len
    character(:), allocatable, intent(out)             :: what
    type(itb_error_t), intent(out)                     :: err
    logical                                            :: ok
    type(itb_stream_t)  :: sess
    integer(c_int64_t)  :: off, slice
    integer             :: got
    logical             :: fin
    integer(c_int8_t), allocatable, target :: scratch(:)

    ok = .false.
    dst_len = 0_c_int64_t
    what = ""
    allocate (scratch(PUMP_SLICE))
    if (encrypt) then
      call itb_encrypt_stream_begin(pipe, sess, err)
    else
      call itb_decrypt_stream_begin(pipe, sess, err)
    end if
    if (.not. itb_ok(err)) then
      what = "StreamBegin"
      return
    end if

    off = 0_c_int64_t
    do while (off < src_len)
      slice = min(int(PUMP_SLICE, c_int64_t), src_len - off)
      call itb_stream_write(sess, src(off + 1_c_int64_t:off + slice), err)
      if (.not. itb_ok(err)) then
        what = "StreamWrite"
        call itb_stream_free(sess)
        return
      end if
      off = off + slice
      do
        call itb_stream_read(sess, scratch, got, fin, err)
        if (.not. itb_ok(err)) then
          what = "StreamRead"
          call itb_stream_free(sess)
          return
        end if
        if (got == 0) exit
        call accumulate(dst, dst_len, scratch, got)
      end do
    end do

    call itb_stream_end(sess, err)
    if (.not. itb_ok(err)) then
      what = "StreamEnd"
      call itb_stream_free(sess)
      return
    end if
    do
      call itb_stream_read(sess, scratch, got, fin, err)
      if (.not. itb_ok(err)) then
        what = "StreamRead"
        call itb_stream_free(sess)
        return
      end if
      call accumulate(dst, dst_len, scratch, got)
      if (fin) exit
    end do
    call itb_stream_free(sess)
    ok = .true.
  end function

  ! First offset at which a and b differ, counted from zero; the
  ! shorter length when one is a prefix of the other.
  function first_difference(a, alen, b, blen) result(off)
    integer(c_int8_t), intent(in)  :: a(:), b(:)
    integer(c_int64_t), intent(in) :: alen, blen
    integer(c_int64_t)             :: off
    integer(c_int64_t) :: n, i

    n = min(alen, blen)
    do i = 1_c_int64_t, n
      if (a(i) /= b(i)) then
        off = i - 1_c_int64_t
        return
      end if
    end do
    off = n
  end function

  ! Up to 16 bytes of buf from off (zero-based) as lowercase hex, or
  ! "-" when buf has no bytes there.
  function hex_window(buf, blen, off) result(s)
    integer(c_int8_t), intent(in)  :: buf(:)
    integer(c_int64_t), intent(in) :: blen, off
    character(:), allocatable      :: s
    character(len=16), parameter   :: HEXDIG = "0123456789abcdef"
    integer(c_int64_t) :: i, last
    integer            :: v

    if (off >= blen) then
      s = "-"
      return
    end if
    last = min(off + 16_c_int64_t, blen)
    s = ""
    do i = off + 1_c_int64_t, last
      v = iand(int(buf(i)), 255)
      s = s//HEXDIG(v / 16 + 1:v / 16 + 1)//HEXDIG(mod(v, 16) + 1:mod(v, 16) + 1)
    end do
  end function

  ! Records a worker error for a failed cipher call.
  subroutine cipher_fail(w, iter, shape, direction, what, err)
    type(worker_t), intent(inout)  :: w
    integer(c_int64_t), intent(in) :: iter
    integer, intent(in)            :: shape
    character(*), intent(in)       :: direction
    character(*), intent(in)       :: what
    type(itb_error_t), intent(in)  :: err
    character(:), allocatable :: head

    head = worker_tag(w%id, iter)//" shape="//shape_name(shape)//": "//direction
    if (len_trim(what) == 0 .or. what == direction) then
      call worker_fail(w, head//": "//itb_error_text(err))
    else
      call worker_fail(w, head//": "//trim(what)//": "//itb_error_text(err))
    end if
  end subroutine

  ! One iteration. In order: refill the plaintext under rotating
  ! mode; take the read lock; pick the surface; encrypt (timed);
  ! decrypt (timed); compare the round-trip with the plaintext; bump
  ! the counters; release the lock. The whole round-trip runs under
  ! the read lock so handle-mutating maintenance (rekey, blob reopen)
  ! never lands between an encrypt and its matching decrypt --
  ! maintenance runs after this returns, from the worker loop.
  function iterate(w, iter) result(ok)
    type(worker_t), intent(inout)  :: w
    integer(c_int64_t), intent(in) :: iter
    logical                        :: ok
    integer(c_int8_t), allocatable :: wire(:), got(:)
    integer(c_int64_t) :: got_len, plain_len, t0
    integer            :: shape
    logical            :: owned
    character(:), allocatable :: what
    type(itb_error_t)  :: err

    ok = .false.
    plain_len = int(size(w%plaintext, kind=c_int64_t), c_int64_t)

    if (cfg%payload_mode == PAYLOAD_ROTATING) then
      if (.not. fill_payload(PAYLOAD_ROTATING, w%seeded, w%rng, w%plaintext)) then
        call worker_fail(w, worker_tag(w%id, iter)//": payload refill: csprng")
        return
      end if
    end if

    call rd_lock()

    ! Shape dispatch. message is one whole-buffer call on the Single
    ! Message Pipeline; stream_one_shot is one whole-buffer call on
    ! the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
    ! which routes to the same one-shot stream entry the Go
    ! harness calls by name); stream opens a session on the same
    ! streaming Pipeline and drives the chunk loop from here. Under
    ! both the three rotate by iteration number so the session path
    ! and the whole-buffer path alternate on one handle inside every
    ! worker -- the cross-path state-reuse hazard this harness exists
    ! to catch.
    shape = cfg%shape
    if (shape == SHAPE_BOTH) then
      select case (int(mod(iter, 3_c_int64_t)))
      case (0)
        shape = SHAPE_STREAM
      case (1)
        shape = SHAPE_MESSAGE
      case default
        shape = SHAPE_STREAM_ONE_SHOT
      end select
    end if

    owned = .false.
    got_len = 0_c_int64_t
    what = ""
    select case (shape)
    case (SHAPE_STREAM)
      t0 = now_ns()
      if (.not. pump(stream_pipe, .true., w%plaintext, plain_len, &
                     w%wire, w%wire_len, what, err)) then
        call cipher_fail(w, iter, shape, "encrypt", what, err)
        call rd_unlock()
        return
      end if
      w%nanos_enc = w%nanos_enc + (now_ns() - t0)
      t0 = now_ns()
      if (.not. pump(stream_pipe, .false., w%wire, w%wire_len, &
                     w%plain, w%plain_len, what, err)) then
        call cipher_fail(w, iter, shape, "decrypt", what, err)
        call rd_unlock()
        return
      end if
      w%nanos_dec = w%nanos_dec + (now_ns() - t0)
      got_len = w%plain_len
    case (SHAPE_STREAM_ONE_SHOT)
      owned = .true.
      t0 = now_ns()
      call itb_encrypt_stream_one_shot(stream_pipe, w%plaintext, wire, err)
      if (.not. itb_ok(err)) then
        call cipher_fail(w, iter, shape, "encrypt", "encrypt", err)
        call rd_unlock()
        return
      end if
      w%nanos_enc = w%nanos_enc + (now_ns() - t0)
      t0 = now_ns()
      call itb_decrypt_stream_one_shot(stream_pipe, wire, got, err)
      if (.not. itb_ok(err)) then
        call cipher_fail(w, iter, shape, "decrypt", "decrypt", err)
        call rd_unlock()
        return
      end if
      w%nanos_dec = w%nanos_dec + (now_ns() - t0)
      got_len = int(size(got, kind=c_int64_t), c_int64_t)
    case (SHAPE_MESSAGE)
      owned = .true.
      t0 = now_ns()
      call itb_encrypt_message(msg_pipe, w%plaintext, wire, err)
      if (.not. itb_ok(err)) then
        call cipher_fail(w, iter, shape, "encrypt", "encrypt", err)
        call rd_unlock()
        return
      end if
      w%nanos_enc = w%nanos_enc + (now_ns() - t0)
      t0 = now_ns()
      call itb_decrypt_message(msg_pipe, wire, got, err)
      if (.not. itb_ok(err)) then
        call cipher_fail(w, iter, shape, "decrypt", "decrypt", err)
        call rd_unlock()
        return
      end if
      w%nanos_dec = w%nanos_dec + (now_ns() - t0)
      got_len = int(size(got, kind=c_int64_t), c_int64_t)
    end select
    ! Failure model. A cipher call that returns a non-OK status is a
    ! worker error: it is recorded, the run is asked to stop, the
    ! other workers finish their in-flight iteration, and the error
    ! is listed in the summary with the FAIL verdict. A round-trip
    ! that returns OK with different bytes is a data mismatch: the
    ! process terminates here, without summary or cleanup, because
    ! the Pipeline state that produced the wrong bytes is the
    ! evidence and nothing that runs afterwards may touch it.
    if (owned) then
      call check_roundtrip(w, iter, shape, plain_len, got, got_len)
    else
      call check_roundtrip(w, iter, shape, plain_len, w%plain, got_len)
    end if

    w%iters = w%iters + 1_c_int64_t
    w%bytes_enc = w%bytes_enc + plain_len
    w%bytes_dec = w%bytes_dec + got_len
    call rd_unlock()
    ok = .true.
  end function

  pure function same_bytes(a, alen, b, blen) result(same)
    integer(c_int8_t), intent(in)  :: a(:), b(:)
    integer(c_int64_t), intent(in) :: alen, blen
    logical                        :: same
    integer(c_int64_t) :: i

    same = .false.
    if (alen /= blen) return
    do i = 1_c_int64_t, alen
      if (a(i) /= b(i)) return
    end do
    same = .true.
  end function

  ! A round-trip whose bytes differ terminates the process on the
  ! spot: the state that produced them is the evidence.
  subroutine check_roundtrip(w, iter, shape, want_len, got, got_len)
    type(worker_t), intent(in)     :: w
    integer(c_int64_t), intent(in) :: iter, want_len, got_len
    integer, intent(in)            :: shape
    integer(c_int8_t), intent(in)  :: got(:)
    integer(c_int64_t) :: offset

    if (same_bytes(w%plaintext, want_len, got, got_len)) return
    offset = first_difference(w%plaintext, want_len, got, got_len)
    call err_line("DATA MISMATCH "//worker_tag(w%id, iter)//" shape="// &
                  shape_name(shape)//": want "//itoa(want_len)// &
                  " bytes, got "//itoa(got_len)// &
                  " bytes, first difference at offset "//itoa(offset)// &
                  ": want "//hex_window(w%plaintext, want_len, offset)// &
                  " got "//hex_window(got, got_len, offset))
    call die(3)
  end subroutine

  ! Iteration 0, counted in the totals; its completion feeds the
  ! post-warmup baselines. A failing warmup still reaches both
  ! barriers, which the OpenMP region requires of every thread, so
  ! the launcher never waits on a worker that has already given up.
  function worker_warmup(id) result(ok)
    integer, intent(in) :: id
    logical             :: ok
    ok = iterate(workers(id), 0_c_int64_t)
  end function

  ! The main loop: iterations until a stop is requested, the deadline
  ! passes, or the fixed per-worker iteration budget (warmup
  ! included) is spent. The stop request and the deadline are both
  ! checked before an iteration starts, so neither interrupts a call
  ! in flight.
  subroutine worker_loop(id)
    integer, intent(in) :: id
    integer(c_int64_t)  :: iter

    iter = 1_c_int64_t
    do
      if (cfg%iterations > 0_c_int64_t) then
        if (iter >= cfg%iterations) exit
      end if
      if (stop_requested) exit
      if (cfg%iterations == 0_c_int64_t) then
        if (now_ns() - run_start_ns >= cfg%duration_ns) then
          stop_requested = .true.
          exit
        end if
      end if
      if (.not. iterate(workers(id), iter)) exit
      if (.not. worker_maintenance(workers(id), iter)) exit
      iter = iter + 1_c_int64_t
    end do
  end subroutine

end module loop_worker
