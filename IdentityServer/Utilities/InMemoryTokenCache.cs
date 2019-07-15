using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IdentityServer
{
    public class InMemoryTokenCache : TokenCache
    {
        private static readonly List<TokenCacheEntry> TokenCacheEntries = new List<TokenCacheEntry>();
        private readonly string _userObjId;
        private TokenCacheEntry _cache;

        public InMemoryTokenCache(string userObjectId)
        {
           // associate the cache to the current user of the web app
            _userObjId = userObjectId;
            
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;
            this.BeforeWrite = BeforeWriteNotification;

            // look up the entry in the DB
            _cache = TokenCacheEntries.FirstOrDefault(c => c.userObjId == _userObjId);
            // place the entry in memory
            Deserialize(_cache?.cacheBits);
        }

        // clean the db of all tokens associated with the user.
        public override void Clear()
        {
            base.Clear();

            var entry = TokenCacheEntries.FirstOrDefault(e => e.userObjId == _userObjId);
            TokenCacheEntries.Remove(entry);
        }

        // Notification raised before ADAL accesses the cache.
        // This is your chance to update the in-memory copy from the DB, if the in-memory version is stale
        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            if (_cache == null)
            {
                // first time access
                _cache = TokenCacheEntries.FirstOrDefault(c => c.userObjId == _userObjId);
            }
            else
            {   
                // retrieve last write from the DB
                var dbCache = TokenCacheEntries.FirstOrDefault(c => c.userObjId == _userObjId);
                             
                // if the in-memory copy is older than the persistent copy, update the in-memory copy
                if (dbCache.LastWrite > _cache.LastWrite)
                    _cache = dbCache;
            }
            Deserialize(_cache?.cacheBits);
        }
        // Notification raised after ADAL accessed the cache.
        // If the HasStateChanged flag is set, ADAL changed the content of the cache
        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if state changed
            if (this.HasStateChanged)
            {
                // retrieve last write from the DB
                _cache = TokenCacheEntries.FirstOrDefault(e => e.userObjId == _userObjId);
                
                if (_cache == null)
                {
                    _cache = new TokenCacheEntry
                    {
                        userObjId = _userObjId,
                    };
                }
                _cache.LastWrite = DateTime.Now;
                _cache.cacheBits = Serialize();

                TokenCacheEntries.RemoveAll(e => e.userObjId == _userObjId);
                TokenCacheEntries.Add(_cache);

                //// update the DB and the lastwrite                
                //db.Entry(Cache).State = Cache.TokenCacheEntryID == 0 ? EntityState.Added : EntityState.Modified;                
                //db.SaveChanges();
                this.HasStateChanged = false;
            }
        }

        private void BeforeWriteNotification(TokenCacheNotificationArgs args)
        {
            // if you want to ensure that no concurrent write take place, use this notification to place a lock on the entry
            var v = args.UniqueId;
        }
    }
}