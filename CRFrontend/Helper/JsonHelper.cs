using System;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Text.Unicode;

namespace CRBackend.Helper
{
    public class JsonHelper
    {
        private static readonly JsonSerializerOptions _options = new JsonSerializerOptions()
        {
            AllowTrailingCommas = true,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
        };



        public static string Serialize(Object obj)
        {
            if(obj == null) return null;
            string result = JsonSerializer.Serialize(obj, _options);
            return result;
        }
        
        public static string SerializeWithPassword(Object obj)
        {
            if(obj == null) return null;

            string pattern = "\"password\":\\s*\"(.*?)\"";
            string replacement = "\"password\": \"*****\"";

            string result = JsonSerializer.Serialize(obj, _options);

            return Regex.Replace(result, pattern, replacement);
        }



        public static T Deserialize<T>(string json)
        {
            T result = JsonSerializer.Deserialize<T>(json, _options);
            return result;
        }
    }
}
