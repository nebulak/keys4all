# -*- mode: python -*-

block_cipher = None


a = Analysis(['ldap_tool.py'],
             pathex=['C:\\Users\\kunz\\Projekte\\VVV-intern\\interne-inhaltliche-arbeiten\\AP5-Implementierung\\Keys4All-Addon\\python_src'],
             binaries=[],
             datas=[],
             hiddenimports=['ldap3'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='ldap_tool',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
