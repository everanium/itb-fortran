! A decrypt session fed a tampered wire fails with a sticky MAC
! failure. Uses a position probe rather than a single bit flip
! because the over-sized container carries CSPRNG residue in the
! non-payload area -- a flip that lands inside the residue is
! architecturally inert (residue is not payload) and the session
! finishes clean. Probing 32 evenly-spaced positions makes the
! all-residue probability negligible; the first position that
! surfaces an error must give ITB_STATUS_MAC_FAILURE and remain
! sticky on subsequent reads.

program test_stream_sticky
  use, intrinsic :: iso_fortran_env, only: error_unit
  use itb
  use itb_test_helpers
  implicit none

  character(*), parameter :: PROFILE = "streaming-aead-triple-mac-v1"
  integer, parameter :: PROBES = 32

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  type(itb_stream_t)   :: sess
  integer(c_int8_t), allocatable :: plain(:), base_wire(:), wire(:)
  integer(c_int8_t), target :: buf(4096)
  integer :: probe, idx, body_start, body_end, stride, n
  integer(c_int) :: first_status
  logical :: fin, finished_clean, got_error

  call itb_pipeline_init(sender, PROFILE, opts, err)
  call expect_ok(err, "init")
  call load_from(sender, receiver, err)
  call expect_ok(err, "open")

  allocate (plain(65536))
  call fill_mod(plain, 227)
  call itb_encrypt_stream_one_shot(sender, plain, base_wire, err)
  call expect_ok(err, "encrypt one-shot")
  call check(size(base_wire) > 128, "wire long enough for probes")

  ! Evenly spread through the wire body; skip the first / last 16
  ! bytes so a hit against the outer envelope framing does not muddy
  ! the observation.
  body_start = 17
  body_end = size(base_wire) - 16
  stride = (body_end - body_start) / PROBES

  do probe = 0, PROBES - 1
    idx = body_start + probe * stride
    wire = base_wire
    wire(idx) = ieor(wire(idx), 1_c_int8_t)

    call itb_decrypt_stream_begin(receiver, sess, err)
    call expect_ok(err, "stream begin")
    ! Ignore write / end status -- the failure may surface on either
    ! side or only on the drain that follows.
    call itb_stream_write(sess, wire, err)
    call itb_stream_end(sess, err)

    finished_clean = .false.
    got_error = .false.
    first_status = ITB_STATUS_OK
    do
      call itb_stream_read(sess, buf, n, fin, err)
      if (.not. itb_ok(err)) then
        got_error = .true.
        first_status = err%status
        exit
      end if
      if (fin) then
        finished_clean = .true.
        exit
      end if
    end do

    if (finished_clean) then
      ! Residue hit at this offset -- try the next probe.
      call itb_stream_free(sess)
      cycle
    end if
    call check(got_error, "read loop exited without error nor finish")
    call check(first_status == ITB_STATUS_MAC_FAILURE, &
        "tampered wire surfaces MAC failure")

    ! Sticky: a subsequent read reports the same status.
    call itb_stream_read(sess, buf, n, fin, err)
    call expect_status(err, first_status, "failure is sticky")
    call itb_stream_free(sess)

    call itb_pipeline_free(receiver)
    call itb_pipeline_free(sender)
    call test_done("test_stream_sticky")
    stop
  end do

  write (error_unit, '(a)') "FAIL: no probe among 32 evenly-spaced "// &
      "positions surfaced a MAC failure"
  error stop 1
end program
