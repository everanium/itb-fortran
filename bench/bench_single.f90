! bench_single.f90 -- Easy Mode Single Ouroboros benchmarks for the
! Fortran binding.
!
! Mirrors the cross-binding bench_single cohort for PRF-grade
! primitives, locked at 1024-bit ITB key width and 16 MiB CSPRNG-filled
! payload. One mixed-primitive variant cycles the BLAKE family across
! the noise / data / start slots with a dedicated lockSeed slot only
! when ITB_LOCKSEED is set, so the no-LockSeed bench arm measures the
! plain mixed-primitive cost without the BitSoup + LockSoup auto-couple.
!
! Run with:
!
!   make bench
!   ./bench/bin/itb-bench-single
!
!   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 ./bench/bin/itb-bench-single
!   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/bin/itb-bench-single
!
!   ITB_BENCH_FILTER=blake3_encrypt ./bench/bin/itb-bench-single
!
! The harness emits one Go-bench-style line per case (name, iters,
! ns/op, MB/s). See bench_common.f90 for the supported environment
! variables and the convergence policy.

module bench_single_state
  ! Per-case state owned by the bench main: encryptor + plaintext +
  ! pre-encrypted ciphertext (decrypt-side cases only). Fortran
  ! procedure pointers do not carry closures, so callables route
  ! through a module-level array indexed by `case_idx`.
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

  ! Heap-resident registry of per-case state. The Single bench has 40
  ! cases (primitives PRF + 1 Mixed) x 4 ops, so `cases_state` is sized at 40
  ! and `cases_state_len` tracks how many slots have been populated.
  integer, parameter :: MAX_CASES = 64
  type(case_state_t), save :: cases_state(MAX_CASES)
  integer,            save :: cases_state_len = 0

contains

  ! Allocates a fresh state slot and returns its index. Callers store
  ! the resulting index in `bench_case_t%case_idx` so the per-iter
  ! callable can retrieve `cases_state(case_idx)`.
  function alloc_state() result(idx)
    integer :: idx
    if (cases_state_len >= MAX_CASES) then
      write (error_unit, "(A)") "bench_single: state registry exhausted"
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

end module bench_single_state


program bench_single
  use, intrinsic :: iso_fortran_env, only: int64, real64, output_unit, error_unit
  use itb_kinds,     only: itb_byte_kind
  use itb_library,   only: itb_set_max_workers, itb_set_nonce_bits
  use itb_encryptor, only: itb_encryptor_t, new_itb_encryptor, &
                           itb_encryptor_mixed_single
  use bench_common,  only: PAYLOAD_16MB, PRIMITIVES_CANONICAL, &
                           PRIMITIVES_CANONICAL_LEN, env_lock_batch, &
                           env_lock_seed, &
                           env_filter, env_min_seconds, &
                           env_nonce_bits, random_bytes, &
                           measure_one, contains_substr, &
                           bench_case_t
  use bench_single_state, only: cases_state, alloc_state, state_destroy_all
  implicit none

  ! Mixed-primitive composition matching the cross-binding Mixed
  ! Single recipe: noise / data / start cycle through the BLAKE
  ! family while Areion takes the dedicated lockSeed slot
  ! when ITB_LOCKSEED is set. Every name resolves to a 256-bit
  ! native hash width so the mixed-constructor width-check passes.
  character(*), parameter :: MIXED_NOISE = "blake3"
  character(*), parameter :: MIXED_DATA  = "blake2s"
  character(*), parameter :: MIXED_START = "blake2b256"
  character(*), parameter :: MIXED_LOCK  = "areion256"

  integer,        parameter :: KEY_BITS  = 1024
  character(*),   parameter :: MAC_NAME  = "hmac-blake3"
  integer(int64), parameter :: PAYLOAD_BYTES = PAYLOAD_16MB

  ! Lazy descriptor for one bench entry. Each descriptor holds the
  ! case name, the primitive string (empty for mixed), the operation
  ! code (1=encrypt, 2=decrypt, 3=encrypt_auth, 4=decrypt_auth),
  ! and a flag for the mixed-primitive variant.
  type :: bench_desc_t
    character(len=128) :: name = " "
    character(len=32)  :: prim = " "
    integer            :: op   = 0
    logical            :: is_mixed = .false.
  end type

  integer, parameter :: TOTAL_DESCS = 40
  integer, parameter :: OP_ENCRYPT       = 1
  integer, parameter :: OP_DECRYPT       = 2
  integer, parameter :: OP_ENCRYPT_AUTH  = 3
  integer, parameter :: OP_DECRYPT_AUTH  = 4

  type(bench_desc_t) :: descs(TOTAL_DESCS)
  type(bench_case_t) :: c
  integer            :: nonce_bits, ndesc, nsel, i
  character(:), allocatable :: flt
  real(real64) :: min_seconds

  nonce_bits = env_nonce_bits(128)
  call itb_set_max_workers(0)
  call itb_set_nonce_bits(nonce_bits)

  write (output_unit, "(A,I0,A,I0,A,A,A,I0,A,A,A)") &
      "# easy_single primitives=", PRIMITIVES_CANONICAL_LEN,           &
      " key_bits=", KEY_BITS,                                          &
      " mac=",      MAC_NAME,                                          &
      " nonce_bits=", nonce_bits,                                      &
      " lockseed=",   merge("on ", "off", env_lock_seed()),            &
      " workers=auto"
  flush(output_unit)

  call build_descs(descs, ndesc)
  flt = env_filter()
  min_seconds = env_min_seconds()

  ! Count selected cases for the header line.
  nsel = 0
  do i = 1, ndesc
    if (len(flt) == 0 .or. contains_substr(trim(descs(i)%name), flt)) then
      nsel = nsel + 1
    end if
  end do

  if (nsel == 0) then
    write (error_unit, "(A,A)") &
      "no bench cases match filter ", &
      trim(merge(flt, "<unset>", len(flt) > 0))
    stop 0
  end if

  write (output_unit, "(A,I0,A,I0,A,F0.3)") &
      "# benchmarks=", nsel, &
      " payload_bytes=", PAYLOAD_BYTES, &
      " min_seconds=", min_seconds
  flush(output_unit)

  ! Lazy loop: build one case at a time, measure, then free.
  do i = 1, ndesc
    if (len(flt) == 0 .or. contains_substr(trim(descs(i)%name), flt)) then
      call state_destroy_all()
      call build_one_case(descs(i), c)
      call measure_one(c, min_seconds)
    end if
  end do
  call state_destroy_all()

contains

  ! Apply the dedicated lockSeed slot when ITB_LOCKSEED is set. Easy
  ! Mode auto-couples BitSoup + LockSoup as a side effect, so no
  ! separate flag calls are issued.
  subroutine apply_lockseed_if_requested(enc)
    type(itb_encryptor_t), intent(inout) :: enc
    if (env_lock_seed()) call enc%set_lock_seed(1)
  end subroutine

  ! Apply the Lock Batch performance mode when ITB_LOCKBATCH is set.
  ! Inert unless Lock Soup is engaged via ITB_LOCKSEED.
  subroutine apply_lockbatch_if_requested(enc)
    type(itb_encryptor_t), intent(inout) :: enc
    if (env_lock_batch()) call enc%set_lock_batch(1)
  end subroutine

  ! Construct a single-primitive 1024-bit Single Ouroboros encryptor
  ! with HMAC-BLAKE3 authentication.
  subroutine build_single_enc(idx, primitive)
    integer,      intent(in) :: idx
    character(*), intent(in) :: primitive
    call new_itb_encryptor(cases_state(idx)%enc, primitive, KEY_BITS, MAC_NAME, 1)
    call apply_lockseed_if_requested(cases_state(idx)%enc)
    call apply_lockbatch_if_requested(cases_state(idx)%enc)
  end subroutine

  ! Construct a mixed-primitive Single Ouroboros encryptor.
  ! `prim_l` (the dedicated lockSeed primitive) is supplied only
  ! when ITB_LOCKSEED is set, so the no-LockSeed bench arm measures
  ! the plain mixed-primitive cost without the BitSoup + LockSoup
  ! auto-couple. The four primitive names share the 256-bit native
  ! hash width.
  subroutine build_mixed_single_enc(idx)
    integer, intent(in) :: idx
    if (env_lock_seed()) then
      call itb_encryptor_mixed_single(cases_state(idx)%enc, MIXED_NOISE,    &
                                       MIXED_DATA, MIXED_START,             &
                                       KEY_BITS, MAC_NAME, prim_l=MIXED_LOCK)
    else
      call itb_encryptor_mixed_single(cases_state(idx)%enc, MIXED_NOISE,    &
                                       MIXED_DATA, MIXED_START,             &
                                       KEY_BITS, MAC_NAME)
    end if
    call apply_lockbatch_if_requested(cases_state(idx)%enc)
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
      call build_mixed_single_enc(idx)
    else
      call build_single_enc(idx, primitive_or_empty)
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
      call build_mixed_single_enc(idx)
    else
      call build_single_enc(idx, primitive_or_empty)
    end if
    call fill_payload(idx)
    ! Pre-encrypt one ciphertext outside the measured loop; the inner
    ! decrypt loop runs against this stable ciphertext.
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
      call build_mixed_single_enc(idx)
    else
      call build_single_enc(idx, primitive_or_empty)
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
      call build_mixed_single_enc(idx)
    else
      call build_single_enc(idx, primitive_or_empty)
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

  ! ----- Descriptor-list assembly (no encryptors / payloads yet) ----

  subroutine build_descs(ds, n_out)
    type(bench_desc_t), intent(out) :: ds(:)
    integer,            intent(out) :: n_out
    integer :: i, idx
    character(:), allocatable :: prim_name, base_name

    idx = 0
    do i = 1, PRIMITIVES_CANONICAL_LEN
      prim_name = trim(PRIMITIVES_CANONICAL(i))
      base_name = "bench_single_" // prim_name // "_1024bit"
      idx = idx + 1
      ds(idx)%name = trim(base_name // "_encrypt_16mb")
      ds(idx)%prim = prim_name;  ds(idx)%op = OP_ENCRYPT;      ds(idx)%is_mixed = .false.
      idx = idx + 1
      ds(idx)%name = trim(base_name // "_decrypt_16mb")
      ds(idx)%prim = prim_name;  ds(idx)%op = OP_DECRYPT;      ds(idx)%is_mixed = .false.
      idx = idx + 1
      ds(idx)%name = trim(base_name // "_encrypt_auth_16mb")
      ds(idx)%prim = prim_name;  ds(idx)%op = OP_ENCRYPT_AUTH; ds(idx)%is_mixed = .false.
      idx = idx + 1
      ds(idx)%name = trim(base_name // "_decrypt_auth_16mb")
      ds(idx)%prim = prim_name;  ds(idx)%op = OP_DECRYPT_AUTH; ds(idx)%is_mixed = .false.
    end do
    base_name = "bench_single_mixed_1024bit"
    idx = idx + 1
    ds(idx)%name = trim(base_name // "_encrypt_16mb")
    ds(idx)%prim = "";  ds(idx)%op = OP_ENCRYPT;      ds(idx)%is_mixed = .true.
    idx = idx + 1
    ds(idx)%name = trim(base_name // "_decrypt_16mb")
    ds(idx)%prim = "";  ds(idx)%op = OP_DECRYPT;      ds(idx)%is_mixed = .true.
    idx = idx + 1
    ds(idx)%name = trim(base_name // "_encrypt_auth_16mb")
    ds(idx)%prim = "";  ds(idx)%op = OP_ENCRYPT_AUTH; ds(idx)%is_mixed = .true.
    idx = idx + 1
    ds(idx)%name = trim(base_name // "_decrypt_auth_16mb")
    ds(idx)%prim = "";  ds(idx)%op = OP_DECRYPT_AUTH; ds(idx)%is_mixed = .true.
    n_out = idx
  end subroutine

  ! Build a single bench_case_t from a descriptor. The state registry
  ! must have been reset (via state_destroy_all) before calling this.
  subroutine build_one_case(d, c)
    type(bench_desc_t), intent(in)  :: d
    type(bench_case_t), intent(out) :: c
    select case (d%op)
    case (OP_ENCRYPT)
      call make_encrypt_case(trim(d%name), trim(d%prim), d%is_mixed, c)
    case (OP_DECRYPT)
      call make_decrypt_case(trim(d%name), trim(d%prim), d%is_mixed, c)
    case (OP_ENCRYPT_AUTH)
      call make_encrypt_auth_case(trim(d%name), trim(d%prim), d%is_mixed, c)
    case (OP_DECRYPT_AUTH)
      call make_decrypt_auth_case(trim(d%name), trim(d%prim), d%is_mixed, c)
    end select
  end subroutine

end program bench_single
