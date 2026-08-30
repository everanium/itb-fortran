! Single Message round trip across every shipped cipher profile at
! small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
! has no cipher surface and is exercised in test_errors instead.

program test_message
  use, intrinsic :: iso_fortran_env, only: int64
  use itb
  use itb_test_helpers
  implicit none

  character(len=40), parameter :: profiles(8) = [ character(len=40) :: &
      "streaming-aead-triple-mac-v1",       &
      "streaming-noaead-triple-v1",         &
      "singlemsg-triple-mac-v1",            &
      "singlemsg-triple-nomac-v1",          &
      "streaming-aead-triple-mac-mixed-v1", &
      "streaming-noaead-triple-mixed-v1",   &
      "singlemsg-triple-mac-mixed-v1",      &
      "singlemsg-triple-nomac-mixed-v1"]
  integer, parameter :: sizes(2) = [4 * 1024, 256 * 1024]

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:), wire(:), back(:)
  character(:), allocatable :: profile
  integer :: p, s

  do p = 1, size(profiles)
    profile = trim(profiles(p))
    call itb_pipeline_init(sender, profile, opts, err)
    call expect_ok(err, "init "//profile)
    call itb_pipeline_open(receiver, profile, sender%blob, opts, err)
    call expect_ok(err, "open "//profile)

    do s = 1, size(sizes)
      allocate (plain(sizes(s)))
      call fill_xorshift(plain, int(sizes(s), int64))
      call itb_encrypt_message(sender, plain, wire, err)
      call expect_ok(err, "encrypt "//profile)
      call itb_decrypt_message(receiver, wire, back, err)
      call expect_ok(err, "decrypt "//profile)
      call check_bytes_equal(back, plain, "round trip "//profile)
      deallocate (plain)
    end do

    call itb_pipeline_free(receiver)
    call itb_pipeline_free(sender)
  end do

  call test_done("test_message")
end program
