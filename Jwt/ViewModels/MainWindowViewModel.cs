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
                    if (c.Value.StartsWith("{"))
                        jwtPayload += '"' + c.Type + "\":" + c.Value + ",";
                    else
                        jwtPayload += '"' + c.Type + "\":\"" + c.Value + "\",";
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

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName]string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
