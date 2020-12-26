using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace it.ncl.netcore.cryptolibrary.Encryption.AES
{
    /// <summary>
    /// Contains a generated KEY and IV
    /// </summary>
    public class AesParamenters
    {
        #region Properties
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }
        #endregion

        public AesParamenters()
        {
            Key = new byte[32];
            IV = new byte[16];
        }

    }
}
