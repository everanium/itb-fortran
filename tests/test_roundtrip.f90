! test_roundtrip.f90 -- generic Seed / MAC / cipher round-trip coverage.
!
! Confirms the Seed, MAC, and low-level encrypt / decrypt entry points
! round-trip plaintext correctly across a representative slice of
! primitives x ITB key-bit widths plus the version / list_hashes /
! constants probes. Per-primitive deep coverage lives in the dedicated
! test_<primitive>.f90 files; this file is the cross-cutting smoke
! suite that catches regressions in shared infrastructure.
!
! The high-level wrappers raise on any non-OK status. Sub-tests that
! intend to OBSERVE a non-OK status (bad hash name, bad key bits,
! seed-width mismatch) drop to the low-level FFI binding from
! `itb_sys` so the explicit failure status can be inspected without
! terminating the test program.

program test_roundtrip
  use itb_kinds
  use itb_seed
  use itb_mac
  use itb_cipher
  use itb_library
  use itb_errors
  use itb_sys, only: itb_decrypt_auth_c, itb_new_seed_c, itb_encrypt_c, &
                      itb_encrypt3_c
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_roundtrip"
  character(*), parameter :: PT_TEXT   = &
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit."

  call test_single_blake3()
  call test_triple_blake3()
  call test_auth_hmac_sha256()
  call test_auth_triple_kmac256()
  call test_seed_components_roundtrip()
  call test_auth_decrypt_tampered()
  call test_seed_free_does_not_panic()
  call test_version()
  call test_list_hashes()
  call test_constants()
  call test_new_and_free()
  call test_bad_hash()
  call test_bad_key_bits()
  call test_seed_width_mismatch()
  call test_triple_seed_width_mismatch()

  call test_pass(TEST_NAME)

contains

  subroutine make_cstring(s, c_arr)
    character(*), intent(in) :: s
    character(kind=c_char), allocatable, intent(out) :: c_arr(:)
    integer :: i
    allocate (c_arr(len_trim(s) + 1))
    do i = 1, len_trim(s)
      c_arr(i) = s(i:i)
    end do
    c_arr(len_trim(s) + 1) = c_null_char
  end subroutine

  function plaintext_bytes() result(p)
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    allocate (p(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      p(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
  end function

  subroutine test_single_blake3()
    integer(itb_byte_kind), target, allocatable :: pt0(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, ds, ss

    pt0 = plaintext_bytes()
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    ct = itb_encrypt(ns, ds, ss, pt0)
    call assert_true(TEST_NAME, "ciphertext length grew", size(ct) > size(pt0))
    pt = itb_decrypt(ns, ds, ss, ct)
    call assert_bytes_eq(TEST_NAME, "single blake3 roundtrip", pt, pt0)
    call ns%destroy(); call ds%destroy(); call ss%destroy()
  end subroutine

  subroutine test_triple_blake3()
    integer(itb_byte_kind), target, allocatable :: pt0(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3

    pt0 = plaintext_bytes()
    call new_itb_seed(ns,  "blake3", 1024)
    call new_itb_seed(d1,  "blake3", 1024)
    call new_itb_seed(d2,  "blake3", 1024)
    call new_itb_seed(d3,  "blake3", 1024)
    call new_itb_seed(st1, "blake3", 1024)
    call new_itb_seed(st2, "blake3", 1024)
    call new_itb_seed(st3, "blake3", 1024)
    ct = itb_encrypt_triple(ns, d1, d2, d3, st1, st2, st3, pt0)
    pt = itb_decrypt_triple(ns, d1, d2, d3, st1, st2, st3, ct)
    call assert_bytes_eq(TEST_NAME, "triple blake3 roundtrip", pt, pt0)
    call ns%destroy()
    call d1%destroy();  call d2%destroy();  call d3%destroy()
    call st1%destroy(); call st2%destroy(); call st3%destroy()
  end subroutine

  subroutine test_auth_hmac_sha256()
    integer(itb_byte_kind), target, allocatable :: pt0(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    integer(itb_byte_kind), target :: key(32)
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac

    pt0 = plaintext_bytes()
    key(:) = 66_itb_byte_kind
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-sha256", key)
    ct = itb_encrypt_auth(ns, ds, ss, mac, pt0)
    pt = itb_decrypt_auth(ns, ds, ss, mac, ct)
    call assert_bytes_eq(TEST_NAME, "auth hmac-sha256 roundtrip", pt, pt0)
    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_auth_triple_kmac256()
    integer(itb_byte_kind), target, allocatable :: pt0(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    integer(itb_byte_kind), target :: key(32)
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3
    type(itb_mac_t)  :: mac

    pt0 = plaintext_bytes()
    key(:) = 33_itb_byte_kind  ! 0x21
    call new_itb_seed(ns,  "blake3", 1024)
    call new_itb_seed(d1,  "blake3", 1024)
    call new_itb_seed(d2,  "blake3", 1024)
    call new_itb_seed(d3,  "blake3", 1024)
    call new_itb_seed(st1, "blake3", 1024)
    call new_itb_seed(st2, "blake3", 1024)
    call new_itb_seed(st3, "blake3", 1024)
    call new_itb_mac(mac, "kmac256", key)
    ct = itb_encrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3, mac, pt0)
    pt = itb_decrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3, mac, ct)
    call assert_bytes_eq(TEST_NAME, "auth triple kmac256 roundtrip", pt, pt0)
    call ns%destroy()
    call d1%destroy();  call d2%destroy();  call d3%destroy()
    call st1%destroy(); call st2%destroy(); call st3%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_seed_components_roundtrip()
    type(itb_seed_t) :: s, s2
    integer(itb_u64_kind),  allocatable :: comps(:), comps2(:)
    integer(itb_byte_kind), allocatable :: key(:),   key2(:)

    call new_itb_seed(s, "blake3", 1024)
    comps = s%components()
    key   = s%hash_key()
    call itb_seed_from_components(s2, "blake3", comps, key)
    comps2 = s2%components()
    key2   = s2%hash_key()
    call assert_u64_array_eq(TEST_NAME, "components round-trip", comps2, comps)
    call assert_bytes_eq(TEST_NAME, "hash_key round-trip", key2, key)
    call s%destroy(); call s2%destroy()
  end subroutine

  subroutine test_auth_decrypt_tampered()
    integer(itb_byte_kind), target, allocatable :: pt0(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), target :: key(32)
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc

    pt0 = plaintext_bytes()
    key(:) = 0_itb_byte_kind
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-sha256", key)
    ct = itb_encrypt_auth(ns, ds, ss, mac, pt0)
    ! Flip the last byte to tamper with the MAC tag.
    ct(size(ct)) = ieor(ct(size(ct)), int(z'FF', itb_byte_kind))
    out_len = 0_itb_size_kind
    rc = itb_decrypt_auth_c(ns%raw_handle(), ds%raw_handle(), ss%raw_handle(), &
                             mac%raw_handle(), c_loc(ct),                      &
                             int(size(ct), itb_size_kind),                     &
                             c_null_ptr, 0_itb_size_kind, out_len)
    call assert_status_eq(TEST_NAME, "tamper rejected", rc, STATUS_MAC_FAILURE)
    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_seed_free_does_not_panic()
    type(itb_seed_t) :: seed
    integer :: i

    do i = 1, 32
      call new_itb_seed(seed, "blake3", 512)
      call seed%destroy()
      ! Idempotent destroy.
      call seed%destroy()
    end do
  end subroutine

  subroutine test_version()
    character(:), allocatable :: ver
    integer :: first_dot, second_dot

    ver = itb_version()
    call assert_true(TEST_NAME, "version non-empty", len(ver) > 0)
    first_dot = index(ver, ".")
    call assert_true(TEST_NAME, "version has first dot", first_dot > 0)
    second_dot = index(ver(first_dot+1:), ".")
    call assert_true(TEST_NAME, "version has second dot", second_dot > 0)
  end subroutine

  subroutine test_list_hashes()
    integer(itb_int32_kind) :: count
    character(*), parameter :: EXPECTED(9) = &
        [character(len=10) :: "areion256", "areion512", "blake2b256",  &
                              "blake2b512", "blake2s",  "blake3",     &
                              "aescmac",   "siphash24", "chacha20"]
    character(:), allocatable :: name
    integer :: i

    count = itb_hash_count()
    call assert_int_eq(TEST_NAME, "hash_count", int(count), 9)
    do i = 1, 9
      name = itb_hash_name(i - 1)
      call assert_string_eq(TEST_NAME, "hash_name", name, trim(EXPECTED(i)))
    end do
  end subroutine

  subroutine test_constants()
    call assert_int_eq(TEST_NAME, "max_key_bits", int(itb_max_key_bits()), 2048)
    call assert_int_eq(TEST_NAME, "channels",     int(itb_channels()),     8)
  end subroutine

  subroutine test_new_and_free()
    type(itb_seed_t) :: s
    character(:), allocatable :: name
    integer(itb_int32_kind) :: width

    call new_itb_seed(s, "blake3", 1024)
    call assert_false(TEST_NAME, "seed live after new", s%is_closed())
    name = s%hash_name()
    call assert_string_eq(TEST_NAME, "seed hash_name", name, "blake3")
    width = s%width()
    call assert_int_eq(TEST_NAME, "seed width", int(width), 256)
    call s%destroy()
  end subroutine

  subroutine test_bad_hash()
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: cname(:)

    call make_cstring("nonsense-hash", cname)
    handle = itb_null_handle
    rc = itb_new_seed_c(c_loc(cname), 1024_c_int, handle)
    call assert_status_eq(TEST_NAME, "bad hash name rejected", rc, STATUS_BAD_HASH)
  end subroutine

  subroutine test_bad_key_bits()
    integer, parameter :: BAD(4) = [0, 256, 511, 2049]
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: cname(:)
    integer :: i

    call make_cstring("blake3", cname)
    do i = 1, size(BAD)
      handle = itb_null_handle
      rc = itb_new_seed_c(c_loc(cname), int(BAD(i), c_int), handle)
      call assert_status_eq(TEST_NAME, "bad key_bits rejected", rc, STATUS_BAD_KEY_BITS)
    end do
  end subroutine

  subroutine test_seed_width_mismatch()
    type(itb_seed_t) :: ns, ds, ss
    integer(itb_byte_kind), target, allocatable :: pt0(:)
    integer(itb_byte_kind), target              :: scratch(4096)
    integer(itb_status_kind) :: rc
    integer(itb_size_kind)   :: out_len
    character(*), parameter :: PT_HELLO = "hello"
    integer :: i

    allocate (pt0(len(PT_HELLO)))
    do i = 1, len(PT_HELLO)
      pt0(i) = int(iachar(PT_HELLO(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(ns, "siphash24", 1024)  ! width 128
    call new_itb_seed(ds, "blake3",    1024)  ! width 256
    call new_itb_seed(ss, "blake3",    1024)  ! width 256

    out_len = 0_itb_size_kind
    rc = itb_encrypt_c(ns%raw_handle(), ds%raw_handle(), ss%raw_handle(), &
                        c_loc(pt0), int(size(pt0), itb_size_kind),         &
                        c_loc(scratch), int(size(scratch), itb_size_kind), &
                        out_len)
    call assert_status_eq(TEST_NAME, "seed width mismatch rejected", &
                           rc, STATUS_SEED_WIDTH_MIX)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
  end subroutine

  subroutine test_triple_seed_width_mismatch()
    type(itb_seed_t) :: odd, r1, r2, r3, r4, r5, r6
    integer(itb_byte_kind), target, allocatable :: pt0(:)
    integer(itb_byte_kind), target              :: scratch(4096)
    integer(itb_status_kind) :: rc
    integer(itb_size_kind)   :: out_len
    character(*), parameter :: PT_HELLO = "hello"
    integer :: i

    allocate (pt0(len(PT_HELLO)))
    do i = 1, len(PT_HELLO)
      pt0(i) = int(iachar(PT_HELLO(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(odd, "siphash24", 1024)
    call new_itb_seed(r1,  "blake3",    1024)
    call new_itb_seed(r2,  "blake3",    1024)
    call new_itb_seed(r3,  "blake3",    1024)
    call new_itb_seed(r4,  "blake3",    1024)
    call new_itb_seed(r5,  "blake3",    1024)
    call new_itb_seed(r6,  "blake3",    1024)

    out_len = 0_itb_size_kind
    rc = itb_encrypt3_c(odd%raw_handle(),                              &
                         r1%raw_handle(), r2%raw_handle(), r3%raw_handle(), &
                         r4%raw_handle(), r5%raw_handle(), r6%raw_handle(), &
                         c_loc(pt0), int(size(pt0), itb_size_kind),         &
                         c_loc(scratch), int(size(scratch), itb_size_kind), &
                         out_len)
    call assert_status_eq(TEST_NAME, "triple seed width mismatch rejected", &
                           rc, STATUS_SEED_WIDTH_MIX)

    call odd%destroy()
    call r1%destroy(); call r2%destroy(); call r3%destroy()
    call r4%destroy(); call r5%destroy(); call r6%destroy()
  end subroutine

end program test_roundtrip
