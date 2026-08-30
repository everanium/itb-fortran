! itb_opts.f90 -- URL-query builder for the opts pass-through string.
!
! The builder performs no validation: every key and value is rendered
! into a percent-encoded query string and passed through to Go
! verbatim; libitb rejects unknown keys or bad values with a
! diagnostic surfaced via itb_error_t. Primitive / MAC / cipher /
! profile names are opaque strings -- the binding never interprets
! them.
!
! Usage:
!
!   type(itb_opts_t) :: opts
!   call itb_opts_set(opts, "nonceBits", "512")
!   call itb_opts_set(opts, "innerHash", "areion512")
!
! The accumulated query is read back via itb_opts_query (empty string
! for a fresh builder = pure profile defaults).

module itb_opts
  implicit none
  private

  public :: itb_opts_t, itb_opts_set, itb_opts_query

  type :: itb_opts_t
    character(:), allocatable :: query
  end type

contains

  ! Append one key=value pair (percent-encoded).
  subroutine itb_opts_set(opts, key, value)
    type(itb_opts_t), intent(inout) :: opts
    character(*), intent(in)        :: key
    character(*), intent(in)        :: value

    if (.not. allocated(opts%query)) opts%query = ""
    if (len(opts%query) > 0) opts%query = opts%query//"&"
    opts%query = opts%query//enc(key)//"="//enc(value)
  end subroutine

  ! The accumulated query string ("" for an empty builder).
  function itb_opts_query(opts) result(q)
    type(itb_opts_t), intent(in) :: opts
    character(:), allocatable    :: q

    if (allocated(opts%query)) then
      q = opts%query
    else
      q = ""
    end if
  end function

  ! Minimal percent-encoding: the accepted values are ASCII names,
  ! decimal integers, true / false, hex, and comma-separated lists,
  ! so everything outside the URL-safe subset (plus ",") is escaped
  ! byte-wise.
  function enc(s) result(out)
    character(*), intent(in)  :: s
    character(:), allocatable :: out
    character(len=1)  :: ch
    character(len=16), parameter :: hexdig = "0123456789ABCDEF"
    integer :: i, code

    out = ""
    do i = 1, len(s)
      ch = s(i:i)
      select case (ch)
      case ('A':'Z', 'a':'z', '0':'9', '-', '.', '_', '~', ',')
        out = out//ch
      case default
        code = iachar(ch)
        out = out//"%"//hexdig(code / 16 + 1:code / 16 + 1) &
                     //hexdig(mod(code, 16) + 1:mod(code, 16) + 1)
      end select
    end do
  end function

end module itb_opts
