using AuthWEBAPI.Entities;
using AuthWEBAPI.Model;
using Microsoft.AspNetCore.Mvc;

namespace AuthWEBAPI.Service
{
    public interface IAuthService
    {
        Task<TokenResponseDTO> LoginAsync(UserDTO request);
        Task<ActionResult<TokenResponseDTO>> RefreshTokenAsync(RefreshTokenResponseDTO request);
        Task<User?> RegisterAsync(UserDTO request);
    }
}