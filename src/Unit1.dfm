object Form1: TForm1
  Left = 196
  Top = 192
  Caption = 'RSA Sample'
  ClientHeight = 689
  ClientWidth = 665
  Color = clBtnFace
  DefaultMonitor = dmDesktop
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object Label2: TLabel
    Left = 16
    Top = 128
    Width = 107
    Height = 13
    Caption = 'Data to encrypt / hash'
  end
  object Label3: TLabel
    Left = 16
    Top = 240
    Width = 74
    Height = 13
    Caption = 'Encrypted Data'
  end
  object Label4: TLabel
    Left = 16
    Top = 352
    Width = 75
    Height = 13
    Caption = 'Decrypted Data'
  end
  object Label5: TLabel
    Left = 16
    Top = 560
    Width = 18
    Height = 13
    Caption = 'Log'
  end
  object Label1: TLabel
    Left = 16
    Top = 464
    Width = 61
    Height = 13
    Caption = 'Hashed data'
  end
  object Label6: TLabel
    Left = 16
    Top = 16
    Width = 53
    Height = 13
    Caption = 'Private key'
  end
  object Label7: TLabel
    Left = 264
    Top = 16
    Width = 49
    Height = 13
    Caption = 'Public key'
  end
  object Memo1: TMemo
    Left = 16
    Top = 144
    Width = 489
    Height = 89
    Lines.Strings = (
      'Some text for RSA Crypt, for 1024 bit key only 117 byte')
    MaxLength = 128
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object Memo2: TMemo
    Left = 16
    Top = 256
    Width = 489
    Height = 89
    ScrollBars = ssVertical
    TabOrder = 1
  end
  object Memo3: TMemo
    Left = 16
    Top = 368
    Width = 489
    Height = 89
    ScrollBars = ssVertical
    TabOrder = 2
  end
  object meLog: TMemo
    Left = 16
    Top = 576
    Width = 633
    Height = 97
    ScrollBars = ssVertical
    TabOrder = 3
  end
  object btnGenerateKeyPair: TButton
    Left = 512
    Top = 32
    Width = 137
    Height = 25
    Caption = 'Generate key pair'
    TabOrder = 4
    OnClick = btnGenerateKeyPairClick
  end
  object btnSha1: TButton
    Left = 512
    Top = 480
    Width = 137
    Height = 25
    Caption = 'SHA1'
    TabOrder = 5
    OnClick = btnSha1Click
  end
  object btnSha256: TButton
    Left = 512
    Top = 504
    Width = 137
    Height = 25
    Caption = 'SHA256'
    TabOrder = 6
    OnClick = btnSha256Click
  end
  object btnSha512: TButton
    Left = 512
    Top = 528
    Width = 137
    Height = 25
    Caption = 'SHA512'
    TabOrder = 7
    OnClick = btnSha512Click
  end
  object Button1: TButton
    Left = 512
    Top = 144
    Width = 137
    Height = 25
    Caption = 'Encrypt with public key'
    TabOrder = 8
    OnClick = Button1Click
  end
  object Button2: TButton
    Left = 512
    Top = 288
    Width = 137
    Height = 25
    Caption = 'Decrypt with private key'
    TabOrder = 9
    OnClick = Button2Click
  end
  object Button3: TButton
    Left = 512
    Top = 176
    Width = 137
    Height = 25
    Caption = 'Encrypt with private key'
    TabOrder = 10
    OnClick = Button3Click
  end
  object Button4: TButton
    Left = 512
    Top = 256
    Width = 137
    Height = 25
    Caption = 'Decrypt with public key'
    TabOrder = 11
    OnClick = Button4Click
  end
  object meHashedInput: TMemo
    Left = 16
    Top = 480
    Width = 489
    Height = 73
    ScrollBars = ssVertical
    TabOrder = 12
  end
  object mePrivateKey: TMemo
    Left = 16
    Top = 32
    Width = 241
    Height = 89
    ScrollBars = ssVertical
    TabOrder = 13
  end
  object mePublicKey: TMemo
    Left = 264
    Top = 32
    Width = 241
    Height = 89
    ScrollBars = ssVertical
    TabOrder = 14
  end
end
