namespace AuthWEBAPI.Model
{
    public class RefreshTokenResponseDTO
    {
        public Guid UserId { get; set; }
        public string RefreshToken { get; set; } = string.Empty;
    }
}
