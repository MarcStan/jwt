using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Text;

namespace Jwt.ViewModels
{
    public class MainWindowViewModel : INotifyPropertyChanged
    {
        private string _jwt;
        private string _input;

        public string Jwt
        {
            get { return _jwt; }
            set
            {
                _jwt = value;
                OnPropertyChanged(nameof(Jwt));
            }
        }

        public string Input
        {
            get { return _input; }
            set
            {
                _input = value;
                OnPropertyChanged(nameof(Input));
                Jwt = Update(Input);
            }
        }

        private string Update(string jwtInput)
        {
            try
            {
                jwtInput = Strip(jwtInput);
                var jwtHandler = new JwtSecurityTokenHandler();

                //Check if readable token (string is in a JWT format)
                var readableToken = jwtHandler.CanReadToken(jwtInput);

                if (!readableToken)
                {
                    return "The token doesn't seem to be in a proper JWT format.";
                }
                var sb = new StringBuilder();
                var token = jwtHandler.ReadJwtToken(jwtInput);

                //Extract the headers of the JWT
                var headers = token.Header;
                var jwtHeader = "{";
                foreach (var h in headers)
                {
                    jwtHeader += '"' + h.Key + "\":\"" + h.Value + "\",";
                }
                jwtHeader += "}";
                sb.Append("Header:\r\n" + JToken.Parse(jwtHeader).ToString(Formatting.Indented));

                //Extract the payload of the JWT
                var claims = token.Claims;
                var jwtPayload = "{";
                foreach (var c in claims)
                {
                    var value = c.Value;
                    if (int.TryParse(value, out int ts))
                    {
                        var time = DateTimeOffset.FromUnixTimeSeconds(ts);
                        value += $" ({time})";

                        if (c.Type == "iat" && time > DateTimeOffset.Now)
                        {
                            value += " NOT VALID YET";
                        }
                        else if (c.Type == "nbf" && time > DateTimeOffset.Now)
                        {
                            value += " NOT VALID YET";
                        }
                        else if (c.Type == "exp" && time < DateTimeOffset.Now)
                        {
                            value += " EXPIRED";
                        }
                    }
                    if (value.StartsWith("{"))
                        jwtPayload += '"' + c.Type + "\":" + value + ",";
                    else
                        jwtPayload += '"' + c.Type + "\":\"" + value + "\",";
                }
                jwtPayload += "}";
                sb.Append("\r\nPayload:\r\n" + JToken.Parse(jwtPayload).ToString(Formatting.Indented));
                return sb.ToString();
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }

        private string Strip(string jwtInput)
        {
            jwtInput = jwtInput.Trim(' ', '\t', '\r', '\n', '}', '{');
            if (jwtInput.StartsWith("Bearer "))
            {
                jwtInput = jwtInput.Substring("Bearer ".Length);
            }
            return jwtInput;
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName]string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
