unit Unit1;
interface
uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ExtCtrls, MMSystem,
  RsaOpenSSL;

type
  TForm1 = class(TForm)
    Memo1: TMemo;
    Memo2: TMemo;
    Memo3: TMemo;
    meLog: TMemo;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    btnSha1: TButton;
    btnSha256: TButton;
    btnSha512: TButton;
    btnGenerateKeyPair: TButton;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    meHashedInput: TMemo;
    Label1: TLabel;
    mePrivateKey: TMemo;
    mePublicKey: TMemo;
    Label6: TLabel;
    Label7: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure btnSha1Click(Sender: TObject);
    procedure btnSha256Click(Sender: TObject);
    procedure btnSha512Click(Sender: TObject);
    procedure btnGenerateKeyPairClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
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
  timeEndPeriod(1);
end;

procedure TForm1.Button1Click(Sender: TObject);
var
  t: Cardinal;
  aRSAData: TRSAData;
begin
  t := timeGetTime;

  aRSAData.DecryptedData := Memo1.Text;
  fRSAOpenSSL.PublicEncrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
    memo2.Lines.Text := aRSAData.EncryptedData;
  meLog.Lines.Add(aRSAData.ErrorMessage);

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

procedure TForm1.Button2Click(Sender: TObject);
var
  t: Cardinal;
  aRSAData: TRSAData;
begin
  t := timeGetTime;

  aRSAData.EncryptedData := Memo2.Text;
  fRSAOpenSSL.PrivateDecrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
    memo3.Lines.Text := aRSAData.DecryptedData;
  meLog.Lines.Add(aRSAData.ErrorMessage);

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

procedure TForm1.Button3Click(Sender: TObject);
var
  t: Cardinal;
  aRSAData: TRSAData;
begin
  t := timeGetTime;

  aRSAData.DecryptedData := Memo1.Text;
  fRSAOpenSSL.PrivateEncrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
    memo2.Lines.Text := aRSAData.EncryptedData;
  meLog.Lines.Add(aRSAData.ErrorMessage);

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

procedure TForm1.Button4Click(Sender: TObject);
var
  t: Cardinal;
  aRSAData: TRSAData;
begin
  t := timeGetTime;

  aRSAData.EncryptedData := Memo2.Text;
  fRSAOpenSSL.PublicDecrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
    memo3.Lines.Text := aRSAData.DecryptedData;
  meLog.Lines.Add(aRSAData.ErrorMessage);

  t := timeGetTime - t;
  meLog.Lines.Append(Format('Done in %dms', [t]));
end;

procedure TForm1.btnSha1Click(Sender: TObject);
begin
  meHashedInput.Text := fRSAOpenSSL.SHA1(Memo1.Text);
end;

procedure TForm1.btnSha256Click(Sender: TObject);
begin
  meHashedInput.Text := fRSAOpenSSL.SHA256(Memo1.Text);
end;

procedure TForm1.btnSha512Click(Sender: TObject);
begin
  meHashedInput.Text := fRSAOpenSSL.SHA512(Memo1.Text);
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
