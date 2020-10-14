using EU.Europa.EC.Markt.Dss.Signature;
using EU.Europa.EC.Markt.Dss.Signature.Cades;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            var document = new FileDocument(@"D:\test.pdf");

            var service = new CAdESService();
            service.SignDocument(document, new SignatureParameters(), null);
        }
    }
}
