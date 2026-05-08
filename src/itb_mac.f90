! itb_mac.f90 -- safe RAII wrapper around the libitb MAC handle.
!
! `type(itb_mac_t)` is the Fortran-side opaque MAC. Note the type's
! `_t` suffix: Fortran resolves bare `type(itb_mac)` to the enclosing
! module name when the module's name matches the type's, so the
! suffix is required to keep the two scopes distinct. The same
! convention applies to `itb_seed_t`, `itb_encryptor_t`,
! `itb_blob128_t` / `itb_blob256_t` / `itb_blob512_t`.
!
! Two-stage lifecycle release pattern (Fortran-only convention):
!
!   * `final :: itb_mac_final`    -- safety-net at end of derived-type
!     scope; non-deterministic across compilers (gfortran / ifx /
!     nvfortran differ on temporaries-during-reallocation, end-of-
!     scope deferral, re-entry behaviour).
!   * `procedure :: destroy`      -- canonical, idempotent. Production
!     code calls `m%destroy()` explicitly when finished.
!
! `itb_mac_t` is move-only by Fortran convention -- assignment
! between `itb_mac_t` instances is not implemented (intrinsic
! structure assignment would copy the handle and lead to double-free
! at `final` time). Pass by reference (`type(itb_mac_t), intent(in)
! :: m`) everywhere or use pointer assignment.

module itb_mac
  use itb_kinds
  use itb_sys
  use itb_strings, only: make_c_string
  use itb_errors,  only: STATUS_OK, STATUS_BAD_HANDLE, raise_itb_error
  implicit none
  private

  public :: itb_mac_t
  public :: new_itb_mac

  type :: itb_mac_t
    private
    integer(itb_handle_kind) :: handle = itb_null_handle
    logical                  :: closed = .true.
  contains
    procedure :: destroy    => itb_mac_destroy
    procedure :: raw_handle => itb_mac_raw_handle
    procedure :: is_closed  => itb_mac_is_closed
    final     :: itb_mac_final
  end type

contains

  ! Construct a MAC from a registered name and a key blob.
  ! `mac_name` is one of "kmac256" / "hmac-sha256" / "hmac-blake3"
  ! (see `itb_list_macs()` for the live list); `key` must satisfy
  ! the primitive's libitb-side requirement: `kmac256` and
  ! `hmac-sha256` accept 16-byte keys and longer; `hmac-blake3`
  ! requires exactly 32 bytes. A 32-byte key is the simplest
  ! cross-primitive choice -- valid for all three.
  !
  ! Subroutine constructor (intent(out)) -- avoids the Fortran
  ! function-result temporary that would otherwise be double-finalised
  ! by the `final ::` hook on this derived type.
  subroutine new_itb_mac(m, mac_name, key)
    type(itb_mac_t),                            intent(out) :: m
    character(*),                               intent(in)  :: mac_name
    integer(itb_byte_kind), target, contiguous, intent(in)  :: key(:)
    character(kind=c_char), allocatable, target :: c_name(:)
    integer(itb_status_kind) :: rc

    m%handle = itb_null_handle
    m%closed = .true.

    call make_c_string(mac_name, c_name)
    rc = itb_new_mac_c(c_loc(c_name),                          &
                       c_loc(key),                              &
                       int(size(key), itb_size_kind),           &
                       m%handle)
    if (rc /= STATUS_OK) then
      m%handle = itb_null_handle
      m%closed = .true.
      call raise_itb_error(rc)
    end if
    m%closed = .false.
  end subroutine

  ! Idempotent release. Calling `destroy` more than once is a no-op.
  subroutine itb_mac_destroy(self)
    class(itb_mac_t), intent(inout) :: self
    integer(itb_status_kind) :: rc

    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      rc = itb_free_mac_c(self%handle)
      ! libitb's free returns OK or BAD_HANDLE; either way the handle
      ! is gone. Don't raise on BAD_HANDLE (caller may have re-entered
      ! destroy from the final hook); raise on anything else.
      if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) call raise_itb_error(rc)
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  ! Safety-net hook -- non-deterministic across compilers. Production
  ! code should not rely on this firing at any specific point.
  subroutine itb_mac_final(self)
    type(itb_mac_t), intent(inout) :: self
    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      block
        integer(itb_status_kind) :: rc
        rc = itb_free_mac_c(self%handle)
        ! Don't propagate errors out of final; final's invocation
        ! timing is non-deterministic and a raise here would surface
        ! at unpredictable program scopes.
      end block
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  function itb_mac_raw_handle(self) result(h)
    class(itb_mac_t), intent(in) :: self
    integer(itb_handle_kind)     :: h
    h = self%handle
  end function

  function itb_mac_is_closed(self) result(b)
    class(itb_mac_t), intent(in) :: self
    logical                      :: b
    b = self%closed
  end function

end module itb_mac
