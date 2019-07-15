using System;

namespace IdentityServer
{
    public class TokenCacheEntry
    {
        public int TokenCacheEntryID { get; set; }
        public string userObjId { get; set; }
        public byte[] cacheBits { get; set; }
        public DateTime LastWrite { get; set; }
    }
}