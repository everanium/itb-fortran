! bench_triple.f90 -- Easy Mode Triple Ouroboros benchmarks for the
! Fortran binding.
!
! Mirrors the cross-binding bench_triple cohort for the nine PRF-grade
! primitives, locked at 1024-bit ITB key width and 16 MiB CSPRNG-filled
! payload. One mixed-primitive variant cycles the BLAKE family across
! the seven seed slots (noise + 3 data + 3 start) plus a dedicated
! lockSeed slot only when ITB_LOCKSEED is set.
!
! Run with:
!
!   make bench
!   ./bench/bin/itb-bench-triple
!
!   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/bin/itb-bench-triple
!
!   ITB_BENCH_FILTER=blake3_encrypt ./bench/bin/itb-bench-triple
!
! The harness emits one Go-bench-style line per case (name, iters,
! ns/op, MB/s). See bench_common.f90 for the supported environment
! variables and the convergence policy.

module bench_triple_state
  ! Per-case state owned by the bench main. Identical shape to
  ! bench_single_state's; the two binaries cannot share a module
  ! because their `cases_state` array sizing and the Triple-side
  ! mixed constructor differ.
  use, intrinsic :: iso_fortran_env, only: int64, error_unit
  use itb_kinds,     only: itb_byte_kind
  use itb_encryptor, only: itb_encryptor_t
  implicit none
  private

  public :: case_state_t
  public :: cases_state
  public :: cases_state_len
  public :: alloc_state
  public :: state_destroy_all

  ! Per-case state. The encryptor is held inline (NOT allocatable)
  ! because ifx's interaction between `intent(out)` constructor
  ! semantics and an allocatable derived-type-component with a
  ! `final ::` binding is fragile -- the final hook can fire on the
  ! pre-allocated component slot in ways that desynchronise the
  ! handle / closed-flag pair the wrapper carries. Inlining the
  ! encryptor sidesteps the allocatable layer entirely; the
  ! `cases_state` array's `save` attribute keeps the wrapper struct
  ! alive for the life of the program.
  type :: case_state_t
    type(itb_encryptor_t)               :: enc
    integer(itb_byte_kind), allocatable :: payload(:)
    integer(itb_byte_kind), allocatable :: ciphertext(:)
  end type

  integer, parameter :: MAX_CASES = 64
  type(case_state_t), save :: cases_state(MAX_CASES)
  integer,            save :: cases_state_len = 0

contains

  function alloc_state() result(idx)
    integer :: idx
    if (cases_state_len >= MAX_CASES) then
      write (error_unit, "(A)") "bench_triple: state registry exhausted"
      error stop 1
    end if
    cases_state_len = cases_state_len + 1
    idx = cases_state_len
  end function

  subroutine state_destroy_all()
    integer :: i
    do i = 1, cases_state_len
      call cases_state(i)%enc%destroy()
      if (allocated(cases_state(i)%payload))    deallocate (cases_state(i)%payload)
      if (allocated(cases_state(i)%ciphertext)) deallocate (cases_state(i)%ciphertext)
    end do
    cases_state_len = 0
  end subroutine

end module bench_triple_state


program bench_triple
  use, intrinsic :: iso_fortran_env, only: int64, output_unit
  use itb_kinds,     only: itb_byte_kind
  use itb_library,   only: itb_set_max_workers, itb_set_nonce_bits
  use itb_encryptor, only: itb_encryptor_t, new_itb_encryptor, &
                           itb_encryptor_mixed_triple
  use bench_common,  only: PAYLOAD_16MB, PRIMITIVES_CANONICAL, &
                           PRIMITIVES_CANONICAL_LEN, env_lock_seed, &
                           env_nonce_bits, random_bytes, run_all, &
                           bench_case_t
  use bench_triple_state, only: cases_state, alloc_state, state_destroy_all
  implicit none

  ! Mixed-primitive composition for Triple Ouroboros. The same four
  ! 256-bit-wide names from the Single bench's Mixed case are cycled
  ! across the seven seed slots, with Areion-SoEM-256 on the dedicated
  ! lockSeed slot when ITB_LOCKSEED is set.
  character(*), parameter :: MIXED_NOISE  = "blake3"
  character(*), parameter :: MIXED_DATA1  = "blake2s"
  character(*), parameter :: MIXED_DATA2  = "blake2b256"
  character(*), parameter :: MIXED_DATA3  = "blake3"
  character(*), parameter :: MIXED_START1 = "blake2s"
  character(*), parameter :: MIXED_START2 = "blake2b256"
  character(*), parameter :: MIXED_START3 = "blake3"
  character(*), parameter :: MIXED_LOCK   = "areion256"

  integer,        parameter :: KEY_BITS  = 1024
  character(*),   parameter :: MAC_NAME  = "hmac-blake3"
  integer(int64), parameter :: PAYLOAD_BYTES = PAYLOAD_16MB

  integer, parameter :: TOTAL_CASES = 40

  type(bench_case_t) :: cases(TOTAL_CASES)
  integer            :: nonce_bits, n

  nonce_bits = env_nonce_bits(128)
  call itb_set_max_workers(0)
  call itb_set_nonce_bits(nonce_bits)

  write (output_unit, "(A,I0,A,I0,A,A,A,I0,A,A,A)") &
      "# easy_triple primitives=", PRIMITIVES_CANONICAL_LEN,           &
      " key_bits=", KEY_BITS,                                          &
      " mac=",      MAC_NAME,                                          &
      " nonce_bits=", nonce_bits,                                      &
      " lockseed=",   merge("on ", "off", env_lock_seed()),            &
      " workers=auto"
  flush(output_unit)

  call build_cases(cases, n)
  call run_all(cases, n)
  call state_destroy_all()

contains

  subroutine apply_lockseed_if_requested(enc)
    type(itb_encryptor_t), intent(inout) :: enc
    if (env_lock_seed()) call enc%set_lock_seed(1)
  end subroutine

  ! Construct a single-primitive 1024-bit Triple Ouroboros encryptor
  ! with HMAC-BLAKE3 authentication (mode = 3, 7 seed slots).
  subroutine build_triple_enc(idx, primitive)
    integer,      intent(in) :: idx
    character(*), intent(in) :: primitive
    call new_itb_encryptor(cases_state(idx)%enc, primitive, KEY_BITS, MAC_NAME, 3)
    call apply_lockseed_if_requested(cases_state(idx)%enc)
  end subroutine

  ! Construct a mixed-primitive Triple Ouroboros encryptor across
  ! the seven seed slots. `prim_l` is supplied only when
  ! ITB_LOCKSEED is set.
  subroutine build_mixed_triple_enc(idx)
    integer, intent(in) :: idx
    if (env_lock_seed()) then
      call itb_encryptor_mixed_triple(cases_state(idx)%enc, MIXED_NOISE,    &
                                       MIXED_DATA1, MIXED_DATA2, MIXED_DATA3, &
                                       MIXED_START1, MIXED_START2, MIXED_START3, &
                                       KEY_BITS, MAC_NAME, prim_l=MIXED_LOCK)
    else
      call itb_encryptor_mixed_triple(cases_state(idx)%enc, MIXED_NOISE,    &
                                       MIXED_DATA1, MIXED_DATA2, MIXED_DATA3, &
                                       MIXED_START1, MIXED_START2, MIXED_START3, &
                                       KEY_BITS, MAC_NAME)
    end if
  end subroutine

  subroutine fill_payload(idx)
    integer, intent(in) :: idx
    integer(int64), allocatable :: scratch(:)
    integer(int64) :: i
    allocate (scratch(PAYLOAD_BYTES))
    call random_bytes(scratch, PAYLOAD_BYTES)
    allocate (cases_state(idx)%payload(PAYLOAD_BYTES))
    do i = 1, PAYLOAD_BYTES
      cases_state(idx)%payload(i) = int(scratch(i), itb_byte_kind)
    end do
    deallocate (scratch)
  end subroutine

  ! ----- Per-iter callables -----------------------------------------

  ! Per-iter callables. The cipher methods take `target, contiguous,
  ! intent(in)` plaintext / ciphertext dummies; the allocatable
  ! component on `cases_state(case_idx)` satisfies both attributes
  ! at the call site under both gfortran and ifx (with the
  ! ifx-specific `-heap-arrays 0` flag set on bench objects so the
  ! 16 MiB auto-reallocation temporary does not overflow the default
  ! 8 MiB Linux stack limit).
  subroutine run_encrypt(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_byte_kind), allocatable :: ct(:)
    do i = 1_int64, iters
      ct = cases_state(case_idx)%enc%encrypt(cases_state(case_idx)%payload)
      if (allocated(ct)) deallocate (ct)
    end do
  end subroutine

  subroutine run_decrypt(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_byte_kind), allocatable :: pt(:)
    do i = 1_int64, iters
      pt = cases_state(case_idx)%enc%decrypt(cases_state(case_idx)%ciphertext)
      if (allocated(pt)) deallocate (pt)
    end do
  end subroutine

  subroutine run_encrypt_auth(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_byte_kind), allocatable :: ct(:)
    do i = 1_int64, iters
      ct = cases_state(case_idx)%enc%encrypt_auth(cases_state(case_idx)%payload)
      if (allocated(ct)) deallocate (ct)
    end do
  end subroutine

  subroutine run_decrypt_auth(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_byte_kind), allocatable :: pt(:)
    do i = 1_int64, iters
      pt = cases_state(case_idx)%enc%decrypt_auth(cases_state(case_idx)%ciphertext)
      if (allocated(pt)) deallocate (pt)
    end do
  end subroutine

  ! ----- Case constructors -----------------------------------------

  subroutine make_encrypt_case(case_label, primitive_or_empty, is_mixed, c)
    character(*),       intent(in)  :: case_label
    character(*),       intent(in)  :: primitive_or_empty
    logical,            intent(in)  :: is_mixed
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    if (is_mixed) then
      call build_mixed_triple_enc(idx)
    else
      call build_triple_enc(idx, primitive_or_empty)
    end if
    call fill_payload(idx)
    c%name = case_label
    c%case_idx = idx
    c%payload_bytes = PAYLOAD_BYTES
    c%run => run_encrypt
  end subroutine

  subroutine make_decrypt_case(case_label, primitive_or_empty, is_mixed, c)
    character(*),       intent(in)  :: case_label
    character(*),       intent(in)  :: primitive_or_empty
    logical,            intent(in)  :: is_mixed
    type(bench_case_t), intent(out) :: c
    integer :: idx
    integer(itb_byte_kind), allocatable :: ct(:)
    idx = alloc_state()
    if (is_mixed) then
      call build_mixed_triple_enc(idx)
    else
      call build_triple_enc(idx, primitive_or_empty)
    end if
    call fill_payload(idx)
    ct = cases_state(idx)%enc%encrypt(cases_state(idx)%payload)
    cases_state(idx)%ciphertext = ct
    deallocate (ct)
    c%name = case_label
    c%case_idx = idx
    c%payload_bytes = PAYLOAD_BYTES
    c%run => run_decrypt
  end subroutine

  subroutine make_encrypt_auth_case(case_label, primitive_or_empty, is_mixed, c)
    character(*),       intent(in)  :: case_label
    character(*),       intent(in)  :: primitive_or_empty
    logical,            intent(in)  :: is_mixed
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    if (is_mixed) then
      call build_mixed_triple_enc(idx)
    else
      call build_triple_enc(idx, primitive_or_empty)
    end if
    call fill_payload(idx)
    c%name = case_label
    c%case_idx = idx
    c%payload_bytes = PAYLOAD_BYTES
    c%run => run_encrypt_auth
  end subroutine

  subroutine make_decrypt_auth_case(case_label, primitive_or_empty, is_mixed, c)
    character(*),       intent(in)  :: case_label
    character(*),       intent(in)  :: primitive_or_empty
    logical,            intent(in)  :: is_mixed
    type(bench_case_t), intent(out) :: c
    integer :: idx
    integer(itb_byte_kind), allocatable :: ct(:)
    idx = alloc_state()
    if (is_mixed) then
      call build_mixed_triple_enc(idx)
    else
      call build_triple_enc(idx, primitive_or_empty)
    end if
    call fill_payload(idx)
    ct = cases_state(idx)%enc%encrypt_auth(cases_state(idx)%payload)
    cases_state(idx)%ciphertext = ct
    deallocate (ct)
    c%name = case_label
    c%case_idx = idx
    c%payload_bytes = PAYLOAD_BYTES
    c%run => run_decrypt_auth
  end subroutine

  ! ----- Case-list assembly ----------------------------------------

  subroutine build_cases(cs, n_out)
    type(bench_case_t), intent(out) :: cs(:)
    integer,            intent(out) :: n_out
    integer :: i, idx
    character(:), allocatable :: prim_name, base_name

    idx = 0
    do i = 1, PRIMITIVES_CANONICAL_LEN
      prim_name = trim(PRIMITIVES_CANONICAL(i))
      base_name = "bench_triple_" // prim_name // "_1024bit"
      idx = idx + 1
      call make_encrypt_case(base_name // "_encrypt_16mb",     prim_name, .false., cs(idx))
      idx = idx + 1
      call make_decrypt_case(base_name // "_decrypt_16mb",     prim_name, .false., cs(idx))
      idx = idx + 1
      call make_encrypt_auth_case(base_name // "_encrypt_auth_16mb", prim_name, .false., cs(idx))
      idx = idx + 1
      call make_decrypt_auth_case(base_name // "_decrypt_auth_16mb", prim_name, .false., cs(idx))
    end do
    base_name = "bench_triple_mixed_1024bit"
    idx = idx + 1
    call make_encrypt_case(base_name // "_encrypt_16mb",     "", .true., cs(idx))
    idx = idx + 1
    call make_decrypt_case(base_name // "_decrypt_16mb",     "", .true., cs(idx))
    idx = idx + 1
    call make_encrypt_auth_case(base_name // "_encrypt_auth_16mb", "", .true., cs(idx))
    idx = idx + 1
    call make_decrypt_auth_case(base_name // "_decrypt_auth_16mb", "", .true., cs(idx))
    n_out = idx
  end subroutine

end program bench_triple
