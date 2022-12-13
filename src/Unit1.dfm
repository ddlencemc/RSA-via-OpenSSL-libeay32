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
  DesignSize = (
    665
    689)
  PixelsPerInch = 96
  TextHeight = 13
  object labelDataToEncryptHash: TLabel
    Left = 16
    Top = 128
    Width = 107
    Height = 13
    Caption = 'Data to encrypt / hash'
  end
  object labelEncryptedData: TLabel
    Left = 16
    Top = 240
    Width = 74
    Height = 13
    Caption = 'Encrypted Data'
  end
  object labelDecryptedData: TLabel
    Left = 16
    Top = 352
    Width = 75
    Height = 13
    Caption = 'Decrypted Data'
  end
  object labelLog: TLabel
    Left = 16
    Top = 560
    Width = 18
    Height = 13
    Caption = 'Log'
  end
  object labelHashedInput: TLabel
    Left = 16
    Top = 464
    Width = 61
    Height = 13
    Caption = 'Hashed data'
  end
  object labelPrivateKey: TLabel
    Left = 16
    Top = 16
    Width = 53
    Height = 13
    Caption = 'Private key'
  end
  object labelPublicKey: TLabel
    Left = 264
    Top = 16
    Width = 49
    Height = 13
    Caption = 'Public key'
  end
  object meDataToEncryptHash: TMemo
    Left = 16
    Top = 144
    Width = 489
    Height = 89
    Anchors = [akLeft, akTop, akRight]
    Lines.Strings = (
      'Some text for RSA Crypt, for 1024 bit key only 117 byte')
    MaxLength = 128
    ScrollBars = ssVertical
    TabOrder = 12
  end
  object meEncryptedData: TMemo
    Left = 16
    Top = 256
    Width = 489
    Height = 89
    Anchors = [akLeft, akTop, akRight]
    ScrollBars = ssVertical
    TabOrder = 13
  end
  object meDecryptedData: TMemo
    Left = 16
    Top = 368
    Width = 489
    Height = 89
    Anchors = [akLeft, akTop, akRight]
    ScrollBars = ssVertical
    TabOrder = 14
  end
  object meLog: TMemo
    Left = 16
    Top = 576
    Width = 633
    Height = 97
    Anchors = [akLeft, akTop, akRight, akBottom]
    ScrollBars = ssVertical
    TabOrder = 16
  end
  object btnGenerateKeyPair: TButton
    Left = 512
    Top = 32
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Generate key pair'
    TabOrder = 0
    OnClick = btnGenerateKeyPairClick
  end
  object btnSha1: TButton
    Left = 512
    Top = 445
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'SHA1'
    TabOrder = 7
    OnClick = btnSha1Click
  end
  object btnSha256: TButton
    Left = 512
    Top = 469
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'SHA256'
    TabOrder = 8
    OnClick = btnSha256Click
  end
  object btnSha512: TButton
    Left = 512
    Top = 493
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'SHA512'
    TabOrder = 9
    OnClick = btnSha512Click
  end
  object btnPublicEncrypt: TButton
    Left = 512
    Top = 144
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Encrypt with public key'
    TabOrder = 1
    OnClick = btnPublicEncryptClick
  end
  object btnPrivateDecrypt: TButton
    Left = 512
    Top = 288
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Decrypt with private key'
    TabOrder = 4
    OnClick = btnPrivateDecryptClick
  end
  object btnPrivateEncrypt: TButton
    Left = 512
    Top = 176
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Encrypt with private key'
    TabOrder = 2
    OnClick = btnPrivateEncryptClick
  end
  object btnPublicDecrypt: TButton
    Left = 512
    Top = 256
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Decrypt with public key'
    TabOrder = 3
    OnClick = btnPublicDecryptClick
  end
  object meHashedInput: TMemo
    Left = 16
    Top = 480
    Width = 489
    Height = 73
    Anchors = [akLeft, akTop, akRight]
    ScrollBars = ssVertical
    TabOrder = 15
  end
  object mePrivateKey: TMemo
    Left = 16
    Top = 32
    Width = 241
    Height = 89
    ScrollBars = ssVertical
    TabOrder = 10
  end
  object mePublicKey: TMemo
    Left = 264
    Top = 32
    Width = 241
    Height = 89
    Anchors = [akLeft, akTop, akRight]
    ScrollBars = ssVertical
    TabOrder = 11
  end
  object btnSHA1_base64: TButton
    Left = 512
    Top = 520
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'SHA1 base64'
    TabOrder = 5
    OnClick = btnSHA1_base64Click
  end
  object btnSHA1_Sign_PK: TButton
    Left = 512
    Top = 544
    Width = 137
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'SHA1 Sign PK'
    TabOrder = 6
    OnClick = btnSHA1_Sign_PKClick
  end
end
