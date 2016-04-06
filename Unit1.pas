unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ExtCtrls, RsaOpenSSL;

type
  TForm1 = class(TForm)
    Panel1: TPanel;
    Panel2: TPanel;
    GroupBox1: TGroupBox;
    GroupBox2: TGroupBox;
    GroupBox3: TGroupBox;
    GroupBox4: TGroupBox;
    Memo1: TMemo;
    Memo2: TMemo;
    Memo3: TMemo;
    Memo4: TMemo;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    Button5: TButton;
    Button6: TButton;
    Button7: TButton;
    procedure FormCreate(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
    procedure Button6Click(Sender: TObject);
    procedure Button7Click(Sender: TObject);
  private
    { Private declarations }
    fRSAOpenSSL : TRSAOpenSSL;
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
var
  aPathToPublickKey, aPathToPrivateKey: string;
begin
  aPathToPublickKey := 'public.pem';
  aPathToPrivateKey := 'private.pem';
  fRSAOpenSSL := TRSAOpenSSL.Create(aPathToPublickKey, aPathToPrivateKey);


end;

procedure TForm1.Button1Click(Sender: TObject);
var
  aRSAData: TRSAData;
begin
  aRSAData.DecryptedData := Memo1.Text;
  fRSAOpenSSL.PublickEncrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
  memo2.Lines.Text := aRSAData.CryptedData;
  memo4.Lines.Add(aRSAData.ErrorMessage);

end;

procedure TForm1.Button2Click(Sender: TObject);
var
  aRSAData: TRSAData;
begin
  aRSAData.CryptedData := Memo2.Text;
  fRSAOpenSSL.PrivateDecrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
  memo3.Lines.Text := aRSAData.DecryptedData;
  memo4.Lines.Add(aRSAData.ErrorMessage);

end;

procedure TForm1.Button3Click(Sender: TObject);
var
  aRSAData: TRSAData;
begin
  aRSAData.DecryptedData := Memo1.Text;
  fRSAOpenSSL.PrivateEncrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
  memo2.Lines.Text := aRSAData.CryptedData;
  memo4.Lines.Add(aRSAData.ErrorMessage);

end;

procedure TForm1.Button4Click(Sender: TObject);
var
  aRSAData: TRSAData;
begin
  aRSAData.CryptedData := Memo2.Text;
  fRSAOpenSSL.PublicDecrypt(aRSAData);
  if aRSAData.ErrorResult = 0 then
  memo3.Lines.Text := aRSAData.DecryptedData;
  memo4.Lines.Add(aRSAData.ErrorMessage);
end;

procedure TForm1.Button5Click(Sender: TObject);
begin
  Memo3.Text := fRSAOpenSSL.SHA1(Memo1.Text);
end;

procedure TForm1.Button6Click(Sender: TObject);
begin
  Memo3.Text := fRSAOpenSSL.SHA256(Memo1.Text);
end;

procedure TForm1.Button7Click(Sender: TObject);
begin
  Memo3.Text := fRSAOpenSSL.SHA512(Memo1.Text);
end;

end.
