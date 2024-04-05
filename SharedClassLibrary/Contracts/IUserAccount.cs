using SharedClassLibrary.DTOs;

namespace SharedClassLibrary.Contracts
{
    public interface IUserAccount
    {
        Task<GeneralResponse> CreateAccount(UserDto userDto);
        Task<LoginResponse> LoginAccount(LoginDto loginDto);
    }
}
