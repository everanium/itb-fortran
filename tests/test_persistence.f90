! test_persistence.f90 -- cross-process persistence round-trip tests.
!
! Exercises the seed component / hash key extraction / re-build path
! across every primitive in the registry x the three ITB key-bit
! widths (512 / 1024 / 2048) that are valid for each native hash
! width. Without both `components` and `hash_key` captured at
! encrypt-side and re-supplied at decrypt-side, the seed state cannot
! be reconstructed and the ciphertext is unreadable.
!
! The high-level wrapper `itb_seed_from_components` raises on any
! non-OK libitb status. The two rejection sub-tests therefore drop to
! the low-level FFI binding (`itb_new_seed_from_components_c` from
! `itb_sys`) so the explicit STATUS_BAD_INPUT branch can be observed
! without terminating the test program.

program test_persistence
  use itb_kinds
  use itb_seed
  use itb_cipher
  use itb_library
  use itb_errors
  use itb_sys, only: itb_new_seed_from_components_c
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_persistence"

  call test_roundtrip_all_hashes()
  call test_random_key_path()
  call test_explicit_key_preserved()
  call test_bad_key_size()
  call test_siphash_rejects_hash_key()

  call test_pass(TEST_NAME)

contains

  function expected_hash_key_len(name) result(n)
    character(*), intent(in) :: name
    integer :: n
    select case (trim(name))
    case ("areion256");  n = 32
    case ("areion512");  n = 64
    case ("blake2b256"); n = 32
    case ("blake2b512"); n = 64
    case ("blake2s");    n = 32
    case ("blake3");     n = 32
    case ("aescmac");    n = 16
    case ("siphash24");  n = 0
    case ("chacha20");   n = 32
    case default;        n = -1
    end select
  end function

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

  subroutine test_roundtrip_all_hashes()
    character(len=10), parameter :: HASHES(9) = &
        [character(len=10) :: "areion256", "areion512", "blake2b256",  &
                              "blake2b512", "blake2s",  "blake3",      &
                              "aescmac",   "siphash24", "chacha20"]
    integer, parameter :: WIDTHS(9) = &
        [256, 512, 256, 512, 256, 256, 128, 128, 256]
    integer, parameter :: CANDIDATE_KB(3) = [512, 1024, 2048]
    character(*), parameter :: PREFIX = "any binary data, including 0x00 bytes -- "
    integer(itb_byte_kind), target,     allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    integer(itb_u64_kind),  allocatable :: ns_comps(:), ds_comps(:), ss_comps(:)
    integer(itb_u64_kind),  allocatable :: ns2_comps(:)
    integer(itb_byte_kind), allocatable :: ns_key(:), ds_key(:), ss_key(:)
    integer(itb_byte_kind), allocatable :: ns2_key(:)
    type(itb_seed_t) :: ns, ds, ss, ns2, ds2, ss2
    integer :: hi, ki, kb, prefix_len, total, p

    prefix_len = len(PREFIX)
    total = prefix_len + 256
    allocate (plaintext(total))
    do p = 1, prefix_len
      plaintext(p) = int(iachar(PREFIX(p:p)), itb_byte_kind)
    end do
    do p = 1, 256
      plaintext(prefix_len + p) = int(iand(int(p - 1, c_int64_t), 255_c_int64_t), &
                                      itb_byte_kind)
    end do

    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle

        ! Day 1 -- random seeds.
        call new_itb_seed(ns, trim(HASHES(hi)), kb)
        call new_itb_seed(ds, trim(HASHES(hi)), kb)
        call new_itb_seed(ss, trim(HASHES(hi)), kb)

        ns_comps = ns%components()
        ds_comps = ds%components()
        ss_comps = ss%components()
        call assert_int_eq(TEST_NAME, "components count*64 == kb", &
                            size(ns_comps) * 64, kb)

        ns_key = ns%hash_key()
        ds_key = ds%hash_key()
        ss_key = ss%hash_key()
        call assert_int_eq(TEST_NAME, "hash_key length matches primitive", &
                            size(ns_key), expected_hash_key_len(trim(HASHES(hi))))

        ct = itb_encrypt(ns, ds, ss, plaintext)
        call ns%destroy(); call ds%destroy(); call ss%destroy()

        ! Day 2 -- restore from saved material.
        call itb_seed_from_components(ns2, trim(HASHES(hi)), ns_comps, ns_key)
        call itb_seed_from_components(ds2, trim(HASHES(hi)), ds_comps, ds_key)
        call itb_seed_from_components(ss2, trim(HASHES(hi)), ss_comps, ss_key)

        pt = itb_decrypt(ns2, ds2, ss2, ct)
        call assert_bytes_eq(TEST_NAME, "persistence roundtrip", pt, plaintext)

        ! Restored seeds report the same components + key.
        ns2_comps = ns2%components()
        call assert_u64_array_eq(TEST_NAME, "ns2 components match", ns2_comps, ns_comps)
        ns2_key = ns2%hash_key()
        call assert_bytes_eq(TEST_NAME, "ns2 hash_key matches", ns2_key, ns_key)

        call ns2%destroy(); call ds2%destroy(); call ss2%destroy()
      end do
    end do
  end subroutine

  subroutine test_random_key_path()
    character(len=10), parameter :: HASHES(9) = &
        [character(len=10) :: "areion256", "areion512", "blake2b256",  &
                              "blake2b512", "blake2s",  "blake3",      &
                              "aescmac",   "siphash24", "chacha20"]
    integer(itb_u64_kind), allocatable :: components(:)
    integer(itb_byte_kind), allocatable :: empty_key(:)
    integer(itb_byte_kind), allocatable :: derived_key(:)
    type(itb_seed_t) :: seed
    integer :: hi, expected

    ! 512-bit zero components -- 8 elements of 64 bits each.
    allocate (components(8))
    components(:) = 0_itb_u64_kind
    allocate (empty_key(0))

    do hi = 1, size(HASHES)
      call itb_seed_from_components(seed, trim(HASHES(hi)), components, empty_key)
      derived_key = seed%hash_key()
      expected = expected_hash_key_len(trim(HASHES(hi)))
      if (trim(HASHES(hi)) == "siphash24") then
        call assert_int_eq(TEST_NAME, "siphash random-key path: zero key", &
                            size(derived_key), 0)
      else
        call assert_int_eq(TEST_NAME, "random-key path: derived key length", &
                            size(derived_key), expected)
      end if
      call seed%destroy()
    end do
  end subroutine

  subroutine test_explicit_key_preserved()
    integer(itb_u64_kind), allocatable :: components(:)
    integer(itb_byte_kind), allocatable :: explicit_key(:)
    integer(itb_byte_kind), allocatable :: got_key(:)
    type(itb_seed_t) :: seed
    integer :: i

    allocate (explicit_key(32))
    do i = 1, 32
      explicit_key(i) = int(i - 1, itb_byte_kind)
    end do
    allocate (components(8))
    components(:) = int(z'CAFEBABEDEADBEEF', itb_u64_kind)

    call itb_seed_from_components(seed, "blake3", components, explicit_key)
    got_key = seed%hash_key()
    call assert_int_eq(TEST_NAME, "explicit-key length", size(got_key), 32)
    call assert_bytes_eq(TEST_NAME, "explicit-key bytes preserved", got_key, explicit_key)
    call seed%destroy()
  end subroutine

  subroutine test_bad_key_size()
    integer(itb_u64_kind),  target, allocatable :: components(:)
    integer(itb_byte_kind), target, allocatable :: bad_key(:)
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: cname(:)

    ! Seven bytes is wrong for blake3 (expects 32). Use the low-level
    ! FFI to observe the rejection without halting via raise.
    allocate (components(16))
    components(:) = 0_itb_u64_kind
    allocate (bad_key(7))
    bad_key(:) = 0_itb_byte_kind
    call make_cstring("blake3", cname)
    handle = itb_null_handle
    rc = itb_new_seed_from_components_c(c_loc(cname),                          &
                                         c_loc(components), int(size(components), c_int), &
                                         c_loc(bad_key),    int(size(bad_key),    c_int), &
                                         handle)
    call assert_true(TEST_NAME, "bad key size rejected", rc /= STATUS_OK)
  end subroutine

  subroutine test_siphash_rejects_hash_key()
    integer(itb_u64_kind),  target, allocatable :: components(:)
    integer(itb_byte_kind), target, allocatable :: nonempty(:)
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: cname(:)

    ! SipHash-2-4 takes no internal fixed key; passing one must be
    ! rejected (not silently ignored).
    allocate (components(8))
    components(:) = 0_itb_u64_kind
    allocate (nonempty(16))
    nonempty(:) = 0_itb_byte_kind
    call make_cstring("siphash24", cname)
    handle = itb_null_handle
    rc = itb_new_seed_from_components_c(c_loc(cname),                          &
                                         c_loc(components), int(size(components), c_int), &
                                         c_loc(nonempty),   int(size(nonempty),   c_int), &
                                         handle)
    call assert_true(TEST_NAME, "siphash rejects hash_key", rc /= STATUS_OK)
  end subroutine

end program test_persistence
