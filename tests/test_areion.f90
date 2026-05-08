! test_areion.f90 -- Areion-SoEM-focused low-level cipher coverage.
!
! Areion-SoEM ships at two ITB hash widths: areion256 (digest 32,
! fixed key 32) and areion512 (digest 64, fixed key 64). The test
! program covers the canonical cross-binding shape across both
! widths: roundtrip across the 128 / 256 / 512 nonce-bit settings,
! Triple Ouroboros roundtrip across the same axis, the authenticated
! counterpart for both Single and Triple (with a tamper step that
! confirms a flipped bit inside the dynamic header region is rejected
! as STATUS_MAC_FAILURE), a persistence sweep that round-trips a
! saved seed via from_components / hash_key, a plaintext-size sweep
! across small + medium + large payloads, and an invariants block
! (width, hash-key length).
!
! The high-level wrappers `itb_encrypt_auth` / `itb_decrypt_auth`
! raise on any non-OK libitb status. The tamper sub-test therefore
! drops to the low-level FFI binding (`itb_decrypt_auth_c` from
! `itb_sys`) so the explicit STATUS_MAC_FAILURE branch can be
! observed without terminating the test program.

program test_areion
  use itb_kinds
  use itb_seed
  use itb_mac
  use itb_cipher
  use itb_library
  use itb_errors
  use itb_sys, only: itb_decrypt_auth_c, itb_decrypt_auth3_c
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_areion"

  ! Canonical (hash, ITB seed-width, fixed-key length) tuples for the
  ! two Areion-SoEM widths.
  integer, parameter :: NUM_HASHES = 2
  character(len=9), parameter :: HASH_NAMES(NUM_HASHES) = &
                          [character(len=9) :: "areion256", "areion512"]
  integer, parameter :: HASH_WIDTHS(NUM_HASHES) = [256, 512]
  integer, parameter :: HASH_KEY_LENS(NUM_HASHES) = [32, 64]

  integer(itb_int32_kind) :: orig_nonce_bits

  orig_nonce_bits = itb_get_nonce_bits()

  call test_roundtrip_across_nonce_sizes()
  call test_triple_roundtrip_across_nonce_sizes()
  call test_auth_across_nonce_sizes()
  call test_triple_auth_across_nonce_sizes()
  call test_persistence_across_nonce_sizes()
  call test_roundtrip_sizes()
  call test_invariants()

  call itb_set_nonce_bits(int(orig_nonce_bits))
  call test_pass(TEST_NAME)

contains

  function token_bytes(n) result(out)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: out(:)
    integer(c_int64_t), save :: ctr = int(z'7EADBEEFCAFEBABE', c_int64_t)
    integer(c_int64_t) :: state
    integer :: i
    integer(c_int64_t), parameter :: GOLD = int(z'7E3779B97F4A7C15', c_int64_t)
    integer(c_int64_t), parameter :: MULT = 6364136223846793005_c_int64_t
    integer(c_int64_t), parameter :: ADDC = 1442695040888963407_c_int64_t

    ctr   = ctr + GOLD
    state = ctr
    if (n <= 0) then
      allocate (out(0))
      return
    end if
    allocate (out(n))
    do i = 1, n
      state  = state * MULT + ADDC
      out(i) = int(iand(ishft(state, -33), 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_roundtrip_across_nonce_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    integer, parameter :: PT_LEN = 1024
    integer(itb_byte_kind), target,     allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: s0, s1, s2
    integer :: i, j
    integer(itb_int32_kind) :: hsize

    plaintext = token_bytes(PT_LEN)
    do i = 1, size(NONCE_SIZES)
      do j = 1, NUM_HASHES
        call itb_set_nonce_bits(NONCE_SIZES(i))
        call new_itb_seed(s0, trim(HASH_NAMES(j)), 1024)
        call new_itb_seed(s1, trim(HASH_NAMES(j)), 1024)
        call new_itb_seed(s2, trim(HASH_NAMES(j)), 1024)
        ct = itb_encrypt(s0, s1, s2, plaintext)
        pt = itb_decrypt(s0, s1, s2, ct)
        call assert_bytes_eq(TEST_NAME, "single roundtrip", pt, plaintext)
        hsize = itb_header_size()
        call assert_true(TEST_NAME, "header size > 0", hsize > 0)
        call assert_true(TEST_NAME, "ct_len >= header_size", size(ct) >= int(hsize))
        call s0%destroy(); call s1%destroy(); call s2%destroy()
      end do
    end do
  end subroutine

  subroutine test_triple_roundtrip_across_nonce_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    integer, parameter :: PT_LEN = 1024
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3
    integer :: i, j

    plaintext = token_bytes(PT_LEN)
    do i = 1, size(NONCE_SIZES)
      do j = 1, NUM_HASHES
        call itb_set_nonce_bits(NONCE_SIZES(i))
        call new_itb_seed(ns,  trim(HASH_NAMES(j)), 1024)
        call new_itb_seed(d1,  trim(HASH_NAMES(j)), 1024)
        call new_itb_seed(d2,  trim(HASH_NAMES(j)), 1024)
        call new_itb_seed(d3,  trim(HASH_NAMES(j)), 1024)
        call new_itb_seed(st1, trim(HASH_NAMES(j)), 1024)
        call new_itb_seed(st2, trim(HASH_NAMES(j)), 1024)
        call new_itb_seed(st3, trim(HASH_NAMES(j)), 1024)
        ct = itb_encrypt_triple(ns, d1, d2, d3, st1, st2, st3, plaintext)
        pt = itb_decrypt_triple(ns, d1, d2, d3, st1, st2, st3, ct)
        call assert_bytes_eq(TEST_NAME, "triple roundtrip", pt, plaintext)
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
    integer(itb_byte_kind), target,     allocatable :: plaintext(:)
    integer(itb_byte_kind), target,     allocatable :: tampered(:)
    integer(itb_byte_kind), target              :: key(32)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: s0, s1, s2
    type(itb_mac_t)  :: mac
    integer :: i, j, m, b, end_b
    integer(itb_int32_kind) :: hsize
    integer(itb_size_kind)  :: out_len
    integer(itb_status_kind) :: rc

    plaintext = token_bytes(PT_LEN)
    do i = 1, size(NONCE_SIZES)
      do m = 1, size(MAC_NAMES)
        do j = 1, NUM_HASHES
          call itb_set_nonce_bits(NONCE_SIZES(i))
          block
            integer(itb_byte_kind), allocatable :: tmp_key(:)
            tmp_key = token_bytes(32)
            key(1:32) = tmp_key(1:32)
          end block
          call new_itb_mac(mac, trim(MAC_NAMES(m)), key)
          call new_itb_seed(s0, trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(s1, trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(s2, trim(HASH_NAMES(j)), 1024)
          ct = itb_encrypt_auth(s0, s1, s2, mac, plaintext)
          pt = itb_decrypt_auth(s0, s1, s2, mac, ct)
          call assert_bytes_eq(TEST_NAME, "single auth roundtrip", pt, plaintext)
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
          rc = itb_decrypt_auth_c(s0%raw_handle(), s1%raw_handle(), s2%raw_handle(), &
                                   mac%raw_handle(), c_loc(tampered),                 &
                                   int(size(tampered), itb_size_kind),                &
                                   c_null_ptr, 0_itb_size_kind, out_len)
          call assert_status_eq(TEST_NAME, "tamper rejection", rc, STATUS_MAC_FAILURE)
          call s0%destroy(); call s1%destroy(); call s2%destroy()
          call mac%destroy()
        end do
      end do
    end do
    if (allocated(tampered)) deallocate (tampered)
  end subroutine

  subroutine test_triple_auth_across_nonce_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    character(len=11), parameter :: MAC_NAMES(3) = &
                          [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    integer, parameter :: PT_LEN = 1024
    integer(itb_byte_kind), target,     allocatable :: plaintext(:)
    integer(itb_byte_kind), target,     allocatable :: tampered(:)
    integer(itb_byte_kind), target              :: key(32)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3
    type(itb_mac_t)  :: mac
    integer :: i, j, m, b, end_b
    integer(itb_int32_kind) :: hsize
    integer(itb_size_kind)  :: out_len
    integer(itb_status_kind) :: rc

    plaintext = token_bytes(PT_LEN)
    do i = 1, size(NONCE_SIZES)
      do m = 1, size(MAC_NAMES)
        do j = 1, NUM_HASHES
          call itb_set_nonce_bits(NONCE_SIZES(i))
          block
            integer(itb_byte_kind), allocatable :: tmp_key(:)
            tmp_key = token_bytes(32)
            key(1:32) = tmp_key(1:32)
          end block
          call new_itb_mac(mac, trim(MAC_NAMES(m)), key)
          call new_itb_seed(ns,  trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(d1,  trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(d2,  trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(d3,  trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(st1, trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(st2, trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(st3, trim(HASH_NAMES(j)), 1024)
          ct = itb_encrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3, mac, plaintext)
          pt = itb_decrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3, mac, ct)
          call assert_bytes_eq(TEST_NAME, "triple auth roundtrip", pt, plaintext)
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
          rc = itb_decrypt_auth3_c(ns%raw_handle(),                               &
                                    d1%raw_handle(),  d2%raw_handle(),  d3%raw_handle(), &
                                    st1%raw_handle(), st2%raw_handle(), st3%raw_handle(),&
                                    mac%raw_handle(), c_loc(tampered),                 &
                                    int(size(tampered), itb_size_kind),                &
                                    c_null_ptr, 0_itb_size_kind, out_len)
          call assert_status_eq(TEST_NAME, "triple tamper rejection", rc, STATUS_MAC_FAILURE)
          call ns%destroy()
          call d1%destroy();  call d2%destroy();  call d3%destroy()
          call st1%destroy(); call st2%destroy(); call st3%destroy()
          call mac%destroy()
        end do
      end do
    end do
    if (allocated(tampered)) deallocate (tampered)
  end subroutine

  subroutine test_persistence_across_nonce_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    integer, parameter :: CANDIDATE_KB(3) = [512, 1024, 2048]
    character(*), parameter :: PREFIX = "persistence payload "
    integer, parameter :: TAIL_LEN = 1024
    integer(itb_byte_kind), target,     allocatable :: plaintext(:), tail(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    integer(itb_u64_kind),  allocatable :: ns_comps(:), ds_comps(:), ss_comps(:)
    integer(itb_byte_kind), allocatable :: ns_key(:), ds_key(:), ss_key(:)
    type(itb_seed_t) :: ns, ds, ss
    integer :: i, j, ki, kb, prefix_len, p, pt_len

    prefix_len = len(PREFIX)
    pt_len     = prefix_len + TAIL_LEN
    allocate (plaintext(pt_len))
    do p = 1, prefix_len
      plaintext(p) = int(iachar(PREFIX(p:p)), itb_byte_kind)
    end do
    tail = token_bytes(TAIL_LEN)
    do p = 1, TAIL_LEN
      plaintext(prefix_len + p) = tail(p)
    end do

    do j = 1, NUM_HASHES
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, HASH_WIDTHS(j)) /= 0) cycle
        do i = 1, size(NONCE_SIZES)
          call itb_set_nonce_bits(NONCE_SIZES(i))
          call new_itb_seed(ns, trim(HASH_NAMES(j)), kb)
          call new_itb_seed(ds, trim(HASH_NAMES(j)), kb)
          call new_itb_seed(ss, trim(HASH_NAMES(j)), kb)
          ns_comps = ns%components()
          ds_comps = ds%components()
          ss_comps = ss%components()
          call assert_int_eq(TEST_NAME, "components count*64 == kb", &
                              size(ns_comps) * 64, kb)
          ns_key = ns%hash_key()
          ds_key = ds%hash_key()
          ss_key = ss%hash_key()
          call assert_int_eq(TEST_NAME, "noise hash_key length", &
                              size(ns_key), HASH_KEY_LENS(j))
          ct = itb_encrypt(ns, ds, ss, plaintext)
          call ns%destroy(); call ds%destroy(); call ss%destroy()
          block
            type(itb_seed_t) :: ns2, ds2, ss2
            call itb_seed_from_components(ns2, trim(HASH_NAMES(j)), ns_comps, ns_key)
            call itb_seed_from_components(ds2, trim(HASH_NAMES(j)), ds_comps, ds_key)
            call itb_seed_from_components(ss2, trim(HASH_NAMES(j)), ss_comps, ss_key)
            pt = itb_decrypt(ns2, ds2, ss2, ct)
            call assert_bytes_eq(TEST_NAME, "persistence roundtrip", pt, plaintext)
            call ns2%destroy(); call ds2%destroy(); call ss2%destroy()
          end block
        end do
      end do
    end do
  end subroutine

  subroutine test_roundtrip_sizes()
    integer, parameter :: NONCE_SIZES(3) = [128, 256, 512]
    integer, parameter :: SIZES(5) = [1, 17, 4096, 65536, 1048576]
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, ds, ss
    integer :: i, j, si, sz

    do j = 1, NUM_HASHES
      do i = 1, size(NONCE_SIZES)
        do si = 1, size(SIZES)
          sz = SIZES(si)
          call itb_set_nonce_bits(NONCE_SIZES(i))
          plaintext = token_bytes(sz)
          call new_itb_seed(ns, trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(ds, trim(HASH_NAMES(j)), 1024)
          call new_itb_seed(ss, trim(HASH_NAMES(j)), 1024)
          ct = itb_encrypt(ns, ds, ss, plaintext)
          pt = itb_decrypt(ns, ds, ss, ct)
          call assert_bytes_eq(TEST_NAME, "size sweep roundtrip", pt, plaintext)
          call ns%destroy(); call ds%destroy(); call ss%destroy()
        end do
      end do
    end do
  end subroutine

  subroutine test_invariants()
    type(itb_seed_t) :: ns, ds, ss
    integer(itb_int32_kind) :: width
    integer(itb_byte_kind), allocatable :: key(:)
    character(:), allocatable :: got_name
    integer :: j

    do j = 1, NUM_HASHES
      call new_itb_seed(ns, trim(HASH_NAMES(j)), 1024)
      call new_itb_seed(ds, trim(HASH_NAMES(j)), 1024)
      call new_itb_seed(ss, trim(HASH_NAMES(j)), 1024)
      width = ns%width()
      call assert_int_eq(TEST_NAME, "width", int(width), HASH_WIDTHS(j))
      got_name = ns%hash_name()
      call assert_string_eq(TEST_NAME, "hash_name", got_name, trim(HASH_NAMES(j)))
      key = ns%hash_key()
      call assert_int_eq(TEST_NAME, "hash_key length", size(key), HASH_KEY_LENS(j))
      call ns%destroy(); call ds%destroy(); call ss%destroy()
    end do
  end subroutine

end program test_areion
