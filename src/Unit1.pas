unit Unit1;
interface
uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ExtCtrls, MMSystem,
  RsaOpenSSL;

type
  TForm1 = class(TForm)
    meDataToEncryptHash: TMemo;
    meEncryptedData: TMemo;
    meDecryptedData: TMemo;
    meLog: TMemo;
    btnPublicEncrypt: TButton;
    btnPrivateDecrypt: TButton;
    btnPrivateEncrypt: TButton;
    btnPublicDecrypt: TButton;
    btnSha1: TButton;
    btnSha256: TButton;
    btnSha512: TButton;
    btnGenerateKeyPair: TButton;
    labelDataToEncryptHash: TLabel;
    labelEncryptedData: TLabel;
    labelDecryptedData: TLabel;
    labelLog: TLabel;
    meHashedInput: TMemo;
    labelHashedInput: TLabel;
    mePrivateKey: TMemo;
    mePublicKey: TMemo;
    labelPrivateKey: TLabel;
    labelPublicKey: TLabel;
    btnSHA1_base64: TButton;
    btnSHA1_Sign_PK: TButton;
    procedure FormCreate(Sender: TObject);
    procedure btnPublicEncryptClick(Sender: TObject);
    procedure btnPrivateDecryptClick(Sender: TObject);
    procedure btnPrivateEncryptClick(Sender: TObject);
    procedure btnPublicDecryptClick(Sender: TObject);
    procedure btnSha1Click(Sender: TObject);
    procedure btnSha256Click(Sender: TObject);
    procedure btnSha512Click(Sender: TObject);
    procedure btnGenerateKeyPairClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnSHA1_base64Click(Sender: TObject);
    procedure btnSHA1_Sign_PKClick(Sender: TObject);
  private
    fRSAOpenSSL: TRSAOpenSSL;
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
var
  aPathToPublickKey, aPathToPrivateKey: string;
begin
  timeBeginPeriod(1);

  aPathToPublickKey := 'public.pem';
  aPathToPrivateKey := 'private.pem';
  fRSAOpenSSL := TRSAOpenSSL.Create(aPathToPublickKey, aPathToPrivateKey);
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  FreeAndNil( fRSAOpenSSL ); // Jacek Mulawka (12.Dec.2022).

  timeEndPeriod(1);
end;

procedure TForm1.btnPublicEncryptClick(Sender: TObject);
var
  t: Cardinal;
  aRSAData: TRSAData;
begin
  t := timeGetTime;

  aRSAData.DecryptedData := meDataToEncryptHash.Text;
  fRSAOpenSSL.PublicEncrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
    meEncryptedData.Lines.Text := aRSAData.EncryptedData;
  meLog.Lines.Add(aRSAData.ErrorMessage);

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

procedure TForm1.btnPrivateDecryptClick(Sender: TObject);
var
  t: Cardinal;
  aRSAData: TRSAData;
begin
  t := timeGetTime;

  aRSAData.EncryptedData := meEncryptedData.Text;
  fRSAOpenSSL.PrivateDecrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
    meDecryptedData.Lines.Text := aRSAData.DecryptedData;
  meLog.Lines.Add(aRSAData.ErrorMessage);

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

procedure TForm1.btnPrivateEncryptClick(Sender: TObject);
var
  t: Cardinal;
  aRSAData: TRSAData;
begin
  t := timeGetTime;

  aRSAData.DecryptedData := meDataToEncryptHash.Text;
  fRSAOpenSSL.PrivateEncrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
    meEncryptedData.Lines.Text := aRSAData.EncryptedData;
  meLog.Lines.Add(aRSAData.ErrorMessage);

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

procedure TForm1.btnPublicDecryptClick(Sender: TObject);
var
  t: Cardinal;
  aRSAData: TRSAData;
begin
  t := timeGetTime;

  aRSAData.EncryptedData := meEncryptedData.Text;
  fRSAOpenSSL.PublicDecrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
    meDecryptedData.Lines.Text := aRSAData.DecryptedData;
  meLog.Lines.Add(aRSAData.ErrorMessage);

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

procedure TForm1.btnSha1Click(Sender: TObject);
begin
  meHashedInput.Text := fRSAOpenSSL.SHA1(meDataToEncryptHash.Text);
end;

procedure TForm1.btnSHA1_base64Click(Sender: TObject);
begin
  meHashedInput.Text := fRSAOpenSSL.SHA1_base64(meDataToEncryptHash.Text);
end;

procedure TForm1.btnSHA1_Sign_PKClick(Sender: TObject);
begin
  meHashedInput.Text := fRSAOpenSSL.SHA1_Sign_PK(meDataToEncryptHash.Text);
end;

procedure TForm1.btnSha256Click(Sender: TObject);
begin
  meHashedInput.Text := fRSAOpenSSL.SHA256(meDataToEncryptHash.Text);
end;

procedure TForm1.btnSha512Click(Sender: TObject);
begin
  meHashedInput.Text := fRSAOpenSSL.SHA512(meDataToEncryptHash.Text);
end;

procedure TForm1.btnGenerateKeyPairClick(Sender: TObject);
var
  t: Cardinal;
  sPublic, sPrivate: string;
begin
  t := timeGetTime;

  fRSAOpenSSL.GenerateKeyPair(1024, sPublic, sPrivate);

  mePrivateKey.Text := sPrivate;
  mePublicKey.Text := sPublic;

  mePrivateKey.Lines.SaveToFile('private.pem');
  mePublicKey.Lines.SaveToFile('public.pem');

  meLog.Lines.Append('Private key saved to private.pem');
  meLog.Lines.Append('Public key saved to public.pem');

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

end.
