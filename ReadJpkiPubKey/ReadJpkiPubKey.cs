using PCSC;
using PCSC.Iso7816;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ReadJpkiPubKey
{
    public partial class ReadJpkiPubKey : Form
    {
        SCardContext mContext;
        IsoReader mReader;

        public ReadJpkiPubKey()
        {
            InitializeComponent();

            //リソースマネージャとの接続
            mContext = new SCardContext();
            mContext.Establish(SCardScope.User);
            mReader = new IsoReader(mContext);
        }

        private void buttonStart_Click(object sender, EventArgs e)
        {
            string[] readerNames = mContext.GetReaders();
            if ((readerNames == null) || (readerNames.Length == 0))
            {
                MessageBox.Show("PC/SC Initialize fail.");
                return;
            }

            string readerName = null;
            foreach (string reader in readerNames)
            {
                if (reader.Length != 0)
                {
                    readerName = reader;
                    break;
                }
            }
            if (readerName == null)
            {
                MessageBox.Show("R/W not Found.");
                return;
            }

            //接続
            mReader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);

            byte[] file = null;
            cardAccess(ref file);

            //切断
            mReader.Disconnect(SCardReaderDisposition.Leave);

            //////////////////////////////////////////////////////////

            int sz = (file[2] << 8) | file[3] + 4;
            System.IO.FileStream fs = new System.IO.FileStream(
                @".\mynumber_pubkey.crt",
                System.IO.FileMode.Create, System.IO.FileAccess.Write);
            fs.Write(file, 0, sz);
            fs.Close();

            Application.Exit();
        }

        private void cardAccess(ref byte[] file)
        {
            Response response;

            //////////////////////////////////////////////////////////

            //SELECT FILE(AP)
            var selectApp = new CommandApdu(IsoCase.Case3Short, SCardProtocol.Any)
            {
                CLA = 0x00,
                Instruction = InstructionCode.SelectFile,
                P1 = (byte)0x04,
                P2 = (byte)0x0c,
                Data = new byte[] { 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01 }
            };
            response = mReader.Transmit(selectApp);
            if ((response.SW1 != 0x90) || (response.SW2 != 0x00))
            {
                MessageBox.Show("SELECT FILE fail(1).");
                return;
            }

            //SELECT FILE(PIN)
            var selectPin = new CommandApdu(IsoCase.Case3Short, SCardProtocol.Any)
            {
                CLA = 0x00,
                Instruction = InstructionCode.SelectFile,
                P1 = (byte)0x02,
                P2 = (byte)0x0c,
                Data = new byte[] { 0x00, 0x0a }
            };
            response = mReader.Transmit(selectPin);
            if ((response.SW1 != 0x90) || (response.SW2 != 0x00))
            {
                MessageBox.Show("SELECT FILE fail(2).");
                return;
            }

            //READ BINARY
            int point = 0;
            int less = -1;
            var readBin = new CommandApdu(IsoCase.Case2Short, SCardProtocol.Any)
            {
                CLA = 0x00,
                Instruction = InstructionCode.ReadBinary,
                P1 = (byte)0x00,
                P2 = (byte)0x00,
                Le = 0xff
            };
            while (true)
            {
                response = mReader.Transmit(readBin);
                byte[] data = null;
                if ((response.SW1 == 0x90) && (response.SW2 == 0x00))
                {
                    data = response.GetData();
                    if (point == 0)
                    {
                        less = (data[2] << 8) | data[3] + 4;
                        file = new byte[less];
                    }
                }
                else
                {
                    MessageBox.Show("SELECT FILE fail(2).");
                    return;
                }

                Buffer.BlockCopy(data, 0, file, point, data.Length);
                point += readBin.Le;
                less -= readBin.Le;
                if (less == 0)
                {
                    break;
                }
                else if (less < readBin.Le)
                {
                    readBin.Le = less;
                }
                readBin.P1 = (byte)((point & 0xff00) >> 8);
                readBin.P2 = (byte)(point & 0x00ff);
            }
        }
    }
}
