! test_nonce_sizes.f90 -- round-trip tests across all nonce-size
! configurations.
!
! ITB exposes a runtime-configurable nonce size (itb_set_nonce_bits)
! that takes one of {128, 256, 512}. The on-the-wire chunk header
! therefore varies between 20, 36, and 68 bytes; every consumer that
! walks ciphertext on the byte level (chunk parsers, tampering tests,
! streaming decoders) must use itb_header_size rather than a
! hardcoded constant.
!
! Per-binary process isolation gives this test program its own libitb
! global state, so the snapshot-and-restore discipline is internal
! hygiene rather than cross-test protection.

program test_nonce_sizes
  use itb_kinds
  use itb_seed
  use itb_mac
  use itb_cipher
  use itb_library
  use itb_errors
  use itb_sys, only: itb_decrypt_auth_c, itb_decrypt_auth3_c, itb_parse_chunk_len_c
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_nonce_sizes"

  integer(itb_int32_kind) :: orig_nonce_bits

  orig_nonce_bits = itb_get_nonce_bits()

  call test_default_is_20()
  call test_header_size_dynamic()
  call test_encrypt_decrypt_across_nonce_sizes()
  call test_triple_encrypt_decrypt_across_nonce_sizes()
  call test_auth_across_nonce_sizes()
  call test_triple_auth_across_nonce_sizes()

  call itb_set_nonce_bits(int(orig_nonce_bits))
  call test_pass(TEST_NAME)

contains

  function pseudo_plaintext(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 31_c_int64_t + 7_c_int64_t
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_default_is_20()
    integer(itb_int32_kind) :: prev
    prev = itb_get_nonce_bits()
    call itb_set_nonce_bits(128)
    call assert_int_eq(TEST_NAME, "default header_size", int(itb_header_size()), 20)
    call assert_int_eq(TEST_NAME, "default nonce_bits", int(itb_get_nonce_bits()), 128)
    call itb_set_nonce_bits(int(prev))
  end subroutine

  subroutine test_header_size_dynamic()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    integer(itb_int32_kind) :: prev
    integer :: i

    prev = itb_get_nonce_bits()
    do i = 1, size(NONCE_SIZES)
      call itb_set_nonce_bits(NONCE_SIZES(i))
      call assert_int_eq(TEST_NAME, "header_size matches nonce/8 + 4", &
                          int(itb_header_size()), NONCE_SIZES(i) / 8 + 4)
    end do
    call itb_set_nonce_bits(int(prev))
  end subroutine

  subroutine test_encrypt_decrypt_across_nonce_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    character(len=10), parameter :: HASHES(3) = &
                          [character(len=10) :: "siphash24", "blake3", "blake2b512"]
    integer, parameter :: PT_LEN = 1024
    integer(itb_byte_kind), target,  allocatable :: plaintext(:)
    integer(itb_byte_kind), target,  allocatable :: ct(:)
    integer(itb_byte_kind), allocatable          :: pt(:)
    type(itb_seed_t) :: ns, ds, ss
    integer :: ni, hi
    integer(itb_size_kind)   :: hsize, chunk_len
    integer(itb_status_kind) :: rc

    plaintext = pseudo_plaintext(PT_LEN)
    do ni = 1, size(NONCE_SIZES)
      do hi = 1, size(HASHES)
        call itb_set_nonce_bits(NONCE_SIZES(ni))
        call new_itb_seed(ns, trim(HASHES(hi)), 1024)
        call new_itb_seed(ds, trim(HASHES(hi)), 1024)
        call new_itb_seed(ss, trim(HASHES(hi)), 1024)
        ct = itb_encrypt(ns, ds, ss, plaintext)
        pt = itb_decrypt(ns, ds, ss, ct)
        call assert_bytes_eq(TEST_NAME, "single roundtrip across nonce", pt, plaintext)

        ! parse_chunk_len must report the full chunk length.
        hsize = int(itb_header_size(), itb_size_kind)
        chunk_len = 0_itb_size_kind
        rc = itb_parse_chunk_len_c(c_loc(ct), hsize, chunk_len)
        call assert_status_ok(TEST_NAME, "parse_chunk_len OK", rc)
        call assert_size_eq(TEST_NAME, "parse_chunk_len matches ct length", &
                             chunk_len, int(size(ct), itb_size_kind))

        call ns%destroy(); call ds%destroy(); call ss%destroy()
      end do
    end do
  end subroutine

  subroutine test_triple_encrypt_decrypt_across_nonce_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    character(len=10), parameter :: HASHES(3) = &
                          [character(len=10) :: "siphash24", "blake3", "blake2b512"]
    integer, parameter :: PT_LEN = 1024
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3
    integer :: ni, hi

    plaintext = pseudo_plaintext(PT_LEN)
    do ni = 1, size(NONCE_SIZES)
      do hi = 1, size(HASHES)
        call itb_set_nonce_bits(NONCE_SIZES(ni))
        call new_itb_seed(ns,  trim(HASHES(hi)), 1024)
        call new_itb_seed(d1,  trim(HASHES(hi)), 1024)
        call new_itb_seed(d2,  trim(HASHES(hi)), 1024)
        call new_itb_seed(d3,  trim(HASHES(hi)), 1024)
        call new_itb_seed(st1, trim(HASHES(hi)), 1024)
        call new_itb_seed(st2, trim(HASHES(hi)), 1024)
        call new_itb_seed(st3, trim(HASHES(hi)), 1024)
        ct = itb_encrypt_triple(ns, d1, d2, d3, st1, st2, st3, plaintext)
        pt = itb_decrypt_triple(ns, d1, d2, d3, st1, st2, st3, ct)
        call assert_bytes_eq(TEST_NAME, "triple roundtrip across nonce", pt, plaintext)
        call ns%destroy()
        call d1%destroy();  call d2%destroy();  call d3%destroy()
        call st1%destroy(); call st2%destroy(); call st3%destroy()
      end do
    end do
  end subroutine

  subroutine test_auth_across_nonce_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    character(len=11), parameter :: MAC_NAMES(3) = &
                          [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    integer, parameter :: PT_LEN = 1024
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: tampered(:)
    integer(itb_byte_kind), target              :: key(32)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer :: ni, mi, b, end_b
    integer(itb_int32_kind)  :: hsize
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc

    plaintext = pseudo_plaintext(PT_LEN)
    key(:) = 115_itb_byte_kind  ! 0x73

    do ni = 1, size(NONCE_SIZES)
      do mi = 1, size(MAC_NAMES)
        call itb_set_nonce_bits(NONCE_SIZES(ni))
        call new_itb_mac(mac, trim(MAC_NAMES(mi)), key)
        call new_itb_seed(ns, "blake3", 1024)
        call new_itb_seed(ds, "blake3", 1024)
        call new_itb_seed(ss, "blake3", 1024)
        ct = itb_encrypt_auth(ns, ds, ss, mac, plaintext)
        pt = itb_decrypt_auth(ns, ds, ss, mac, ct)
        call assert_bytes_eq(TEST_NAME, "auth single roundtrip", pt, plaintext)

        hsize = itb_header_size()
        end_b = int(hsize) + 256
        if (end_b > size(ct)) end_b = size(ct)
        if (allocated(tampered)) deallocate (tampered)
        allocate (tampered(size(ct)))
        tampered(:) = ct(:)
        do b = int(hsize) + 1, end_b
          tampered(b) = ieor(tampered(b), 1_itb_byte_kind)
        end do
        out_len = 0_itb_size_kind
        rc = itb_decrypt_auth_c(ns%raw_handle(), ds%raw_handle(), ss%raw_handle(), &
                                 mac%raw_handle(), c_loc(tampered),                 &
                                 int(size(tampered), itb_size_kind),                &
                                 c_null_ptr, 0_itb_size_kind, out_len)
        call assert_status_eq(TEST_NAME, "tamper rejected", rc, STATUS_MAC_FAILURE)

        call ns%destroy(); call ds%destroy(); call ss%destroy()
        call mac%destroy()
      end do
    end do
    if (allocated(tampered)) deallocate (tampered)
  end subroutine

  subroutine test_triple_auth_across_nonce_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    character(len=11), parameter :: MAC_NAMES(3) = &
                          [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    integer, parameter :: PT_LEN = 1024
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: tampered(:)
    integer(itb_byte_kind), target              :: key(32)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3
    type(itb_mac_t)  :: mac
    integer :: ni, mi, b, end_b
    integer(itb_int32_kind)  :: hsize
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc

    plaintext = pseudo_plaintext(PT_LEN)
    key(:) = 115_itb_byte_kind

    do ni = 1, size(NONCE_SIZES)
      do mi = 1, size(MAC_NAMES)
        call itb_set_nonce_bits(NONCE_SIZES(ni))
        call new_itb_mac(mac, trim(MAC_NAMES(mi)), key)
        call new_itb_seed(ns,  "blake3", 1024)
        call new_itb_seed(d1,  "blake3", 1024)
        call new_itb_seed(d2,  "blake3", 1024)
        call new_itb_seed(d3,  "blake3", 1024)
        call new_itb_seed(st1, "blake3", 1024)
        call new_itb_seed(st2, "blake3", 1024)
        call new_itb_seed(st3, "blake3", 1024)
        ct = itb_encrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3, mac, plaintext)
        pt = itb_decrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3, mac, ct)
        call assert_bytes_eq(TEST_NAME, "auth triple roundtrip", pt, plaintext)

        hsize = itb_header_size()
        end_b = int(hsize) + 256
        if (end_b > size(ct)) end_b = size(ct)
        if (allocated(tampered)) deallocate (tampered)
        allocate (tampered(size(ct)))
        tampered(:) = ct(:)
        do b = int(hsize) + 1, end_b
          tampered(b) = ieor(tampered(b), 1_itb_byte_kind)
        end do
        out_len = 0_itb_size_kind
        rc = itb_decrypt_auth3_c(ns%raw_handle(),                                       &
                                  d1%raw_handle(),  d2%raw_handle(),  d3%raw_handle(),  &
                                  st1%raw_handle(), st2%raw_handle(), st3%raw_handle(), &
                                  mac%raw_handle(), c_loc(tampered),                    &
                                  int(size(tampered), itb_size_kind),                   &
                                  c_null_ptr, 0_itb_size_kind, out_len)
        call assert_status_eq(TEST_NAME, "triple tamper rejected", rc, STATUS_MAC_FAILURE)

        call ns%destroy()
        call d1%destroy();  call d2%destroy();  call d3%destroy()
        call st1%destroy(); call st2%destroy(); call st3%destroy()
        call mac%destroy()
      end do
    end do
    if (allocated(tampered)) deallocate (tampered)
  end subroutine

end program test_nonce_sizes
