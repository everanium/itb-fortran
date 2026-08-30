! Explicit write / end / read round trip with pathological batch
! sizes (17-byte feed, 23-byte drain) across multiple chunks.

program test_stream_incremental
  use itb
  use itb_test_helpers
  implicit none

  character(*), parameter :: PROFILE = "streaming-aead-triple-mac-v1"
  integer, parameter :: PAYLOAD = 65536

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:), wire(:), back(:)

  ! Small chunk size so the payload spans many chunks.
  call itb_opts_set(opts, "chunkSize", "4096")
  call itb_pipeline_init(sender, PROFILE, opts, err)
  call expect_ok(err, "init")
  call itb_pipeline_open(receiver, PROFILE, sender%blob, opts, err)
  call expect_ok(err, "open")

  allocate (plain(PAYLOAD))
  call fill_mod(plain, 241)

  call feed_and_drain(sender, .true., plain, wire)
  call check(size(wire) > 0, "wire non-empty")
  call feed_and_drain(receiver, .false., wire, back)
  call check_bytes_equal(back, plain, "incremental round trip")

  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)
  call test_done("test_stream_incremental")

contains

  ! 17-byte writes, then end + 23-byte drains into dst.
  subroutine feed_and_drain(pipe, encrypt, src, dst)
    type(itb_pipeline_t), intent(in)            :: pipe
    logical, intent(in)                         :: encrypt
    integer(c_int8_t), intent(in)               :: src(:)
    integer(c_int8_t), allocatable, intent(out) :: dst(:)
    type(itb_stream_t)        :: sess
    type(itb_error_t)         :: serr
    integer(c_int8_t), target :: buf(23)
    integer(c_int8_t), allocatable :: acc(:)
    integer :: lo, hi, n, used
    logical :: fin

    if (encrypt) then
      call itb_encrypt_stream_begin(pipe, sess, serr)
    else
      call itb_decrypt_stream_begin(pipe, sess, serr)
    end if
    call expect_ok(serr, "stream begin")

    lo = 1
    do while (lo <= size(src))
      hi = min(lo + 16, size(src))
      call itb_stream_write(sess, src(lo:hi), serr)
      call expect_ok(serr, "stream write")
      lo = hi + 1
    end do
    call itb_stream_end(sess, serr)
    call expect_ok(serr, "stream end")

    allocate (acc(0))
    used = 0
    do
      call itb_stream_read(sess, buf, n, fin, serr)
      call expect_ok(serr, "stream read")
      if (n > 0) then
        acc = [acc(1:used), buf(1:n)]
        used = used + n
      end if
      if (fin) exit
    end do
    call itb_stream_free(sess)
    dst = acc(1:used)
  end subroutine

end program
