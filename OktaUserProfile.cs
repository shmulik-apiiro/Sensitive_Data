#nullable disable 

using Newtonsoft.Json;

namespace AccountService.Okta.Models; 

public class OktaUserProfile
{
    [JsonProperty("login")]
    public string Login { get; set; }

    [JsonProperty("email")]
    public string Email { get; set; }

    [JsonProperty("firstName")]
    public string FirstName { get; set; }

    [JsonProperty("lastName")]
    public string LastName { get; set; }
}
