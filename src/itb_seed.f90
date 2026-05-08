! itb_seed.f90 -- safe RAII wrapper around the libitb noise-seed
! handle. Mirrors the C binding's `itb_seed_*` surface.
!
! `type(itb_seed_t)` is the Fortran-side opaque seed. The type carries
! a `_t` suffix to distinguish it from the enclosing module name --
! Fortran resolves bare `type(itb_seed)` to the module when the two
! names collide.
!
! Two construction paths (both subroutines, NOT functions, to avoid
! the finalization-on-function-return double-free trap):
!
!   1. CSPRNG-keyed:  `call new_itb_seed(s, "blake3", 1024)`
!   2. Deterministic: `call itb_seed_from_components(s, "blake3", comps, hash_key)`
!      -- canonical persistence-restore path; the components and
!      hash key together uniquely re-key the seed.
!
! Subroutine-with-`intent(out)` is the canonical Fortran idiom for
! handle-owning derived types: the destination is initialized in
! place, no function-result temporary is created, no premature
! finalisation runs on a value that has just been "moved" into the
! caller's variable.
!
! Two-stage lifecycle release pattern (Fortran-only convention):
!
!   * Production code calls `s%destroy()` explicitly when finished --
!     this is the canonical lifecycle release.
!   * `final :: itb_seed_final` is shipped as a safety net but its
!     invocation timing is not deterministic across gfortran / ifx /
!     nvfortran. Production code does not rely on the final hook
!     firing at any specific point.
!
! All three (Single Ouroboros) or seven (Triple Ouroboros) seeds
! consumed by the cipher entry points must share the same native
! hash width; mixing widths makes the call raise with
! `STATUS_SEED_WIDTH_MIX`.

module itb_seed
  use itb_kinds
  use itb_sys
  use itb_strings, only: c_buffer_to_fortran_string, make_c_string
  use itb_errors,  only: STATUS_OK, STATUS_BAD_HANDLE, STATUS_BUFFER_TOO_SMALL, raise_itb_error
  implicit none
  private

  public :: itb_seed_t
  public :: new_itb_seed
  public :: itb_seed_from_components

  type :: itb_seed_t
    private
    integer(itb_handle_kind) :: handle = itb_null_handle
    logical                  :: closed = .true.
  contains
    procedure :: destroy           => itb_seed_destroy
    procedure :: raw_handle        => itb_seed_raw_handle
    procedure :: is_closed         => itb_seed_is_closed
    procedure :: width             => itb_seed_width
    procedure :: hash_name         => itb_seed_hash_name
    procedure :: components        => itb_seed_components
    procedure :: hash_key          => itb_seed_hash_key
    procedure :: attach_lock_seed  => itb_seed_attach_lock_seed
    final     :: itb_seed_final
  end type

contains

  subroutine new_itb_seed(s, hash_name, key_bits)
    type(itb_seed_t), intent(out) :: s
    character(*),     intent(in)  :: hash_name
    integer,          intent(in)  :: key_bits
    character(kind=c_char), allocatable, target :: c_name(:)
    integer(itb_status_kind) :: rc

    s%handle = itb_null_handle
    s%closed = .true.

    call make_c_string(hash_name, c_name)
    rc = itb_new_seed_c(c_loc(c_name), int(key_bits, c_int), s%handle)
    if (rc /= STATUS_OK) then
      s%handle = itb_null_handle
      s%closed = .true.
      call raise_itb_error(rc)
    end if
    s%closed = .false.
  end subroutine

  ! Build a seed from caller-supplied uint64 components and an optional
  ! fixed hash key. `components` length must be 8..32 (multiple of 8).
  ! `hash_key` length, when non-empty, must match the primitive's
  ! native fixed-key size: 16 (`aescmac`), 32 (`areion256` / `blake3` /
  ! `blake2{s,b256}` / `chacha20`), 64 (`areion512` / `blake2b512`).
  ! Pass an empty `hash_key` for `siphash24` or to request a CSPRNG-
  ! generated key while keeping deterministic components.
  subroutine itb_seed_from_components(s, hash_name, components, hash_key)
    type(itb_seed_t),               intent(out)    :: s
    character(*),                   intent(in)     :: hash_name
    integer(itb_u64_kind),  target, contiguous, intent(in)     :: components(:)
    integer(itb_byte_kind), target, contiguous, intent(in)     :: hash_key(:)
    character(kind=c_char), allocatable, target :: c_name(:)
    type(c_ptr) :: comp_ptr, key_ptr
    integer(itb_status_kind) :: rc

    s%handle = itb_null_handle
    s%closed = .true.

    call make_c_string(hash_name, c_name)
    if (size(components) > 0) then
      comp_ptr = c_loc(components)
    else
      comp_ptr = c_null_ptr
    end if
    if (size(hash_key) > 0) then
      key_ptr = c_loc(hash_key)
    else
      key_ptr = c_null_ptr
    end if
    rc = itb_new_seed_from_components_c(c_loc(c_name),                       &
                                          comp_ptr, int(size(components), c_int), &
                                          key_ptr,  int(size(hash_key),  c_int),  &
                                          s%handle)
    if (rc /= STATUS_OK) then
      s%handle = itb_null_handle
      s%closed = .true.
      call raise_itb_error(rc)
    end if
    s%closed = .false.
  end subroutine

  subroutine itb_seed_destroy(self)
    class(itb_seed_t), intent(inout) :: self
    integer(itb_status_kind) :: rc

    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      rc = itb_free_seed_c(self%handle)
      if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) call raise_itb_error(rc)
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  ! Safety-net hook -- non-deterministic across compilers. Errors are
  ! swallowed because final's invocation timing means a raise here
  ! would surface at unpredictable program scopes.
  subroutine itb_seed_final(self)
    type(itb_seed_t), intent(inout) :: self
    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      block
        integer(itb_status_kind) :: rc
        rc = itb_free_seed_c(self%handle)
      end block
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  function itb_seed_raw_handle(self) result(h)
    class(itb_seed_t), intent(in) :: self
    integer(itb_handle_kind)      :: h
    h = self%handle
  end function

  function itb_seed_is_closed(self) result(b)
    class(itb_seed_t), intent(in) :: self
    logical                       :: b
    b = self%closed
  end function

  ! ITB_SeedWidth's signature is inverted from the rest of the FFI:
  ! the C return value carries the WIDTH (256 / 512 / 0-on-bad-handle)
  ! and the `outStatus` out-parameter carries the libitb status code.
  ! Mirror that semantic in the wrapper -- check the status, then
  ! return the width.
  function itb_seed_width(self) result(w)
    class(itb_seed_t), intent(in) :: self
    integer(itb_int32_kind)       :: w
    integer(itb_status_kind) :: st
    w = itb_seed_width_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_seed_hash_name(self) result(s)
    class(itb_seed_t), intent(in) :: self
    character(:), allocatable     :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    out_len = 0_itb_size_kind
    rc = itb_seed_hash_name_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)
    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_seed_hash_name_c(self%handle, c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  function itb_seed_components(self) result(comps)
    class(itb_seed_t), intent(in) :: self
    integer(itb_u64_kind), allocatable :: comps(:)
    integer(itb_u64_kind), allocatable, target :: scratch(:)
    integer(itb_int32_kind) :: cap_count, out_count
    integer(itb_status_kind) :: rc
    integer :: i

    out_count = 0
    rc = itb_get_seed_components_c(self%handle, c_null_ptr, 0, out_count)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_count <= 0) then
      allocate (comps(0))
      return
    end if
    cap_count = out_count
    allocate (scratch(cap_count))
    rc = itb_get_seed_components_c(self%handle, c_loc(scratch), cap_count, out_count)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (comps(out_count))
    do i = 1, out_count
      comps(i) = scratch(i)
    end do
  end function

  function itb_seed_hash_key(self) result(key)
    class(itb_seed_t), intent(in) :: self
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    out_len = 0_itb_size_kind
    rc = itb_get_seed_hash_key_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_get_seed_hash_key_c(self%handle, c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  ! Wires a dedicated lockSeed onto this noise seed. The lockSeed has
  ! no observable effect on the wire output unless the bit-permutation
  ! overlay is engaged via `itb_set_bit_soup(1)` or
  ! `itb_set_lock_soup(1)` BEFORE the first encrypt / decrypt call.
  ! Both seeds must share the same native hash width.
  !
  ! The lock seed must outlive the noise seed it is attached to;
  ! destroying the lock seed first leaves a dangling pointer inside
  ! libitb's internal noise-seed state and is undefined behaviour.
  ! The caller is responsible for ordering destroy() calls correctly.
  subroutine itb_seed_attach_lock_seed(self, lock)
    class(itb_seed_t), intent(inout) :: self
    type(itb_seed_t),  intent(in)    :: lock
    integer(itb_status_kind) :: rc
    rc = itb_attach_lock_seed_c(self%handle, lock%handle)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

end module itb_seed
