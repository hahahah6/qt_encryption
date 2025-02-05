QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17
# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    applink.c \
    decode.cpp \
    encryption.cpp \
    main.cpp \
    mainwindow.cpp \
    secret_key.cpp

HEADERS += \
    decode.h \
    encryption.h \
    mainwindow.h \
    secret_key.h

FORMS += \
    decode.ui \
    encryption.ui \
    mainwindow.ui \
    secret_key.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target




win32: LIBS += -L$$PWD/../../qt/Tools/OpenSSLv3/Win_x64/lib/ -llibcrypto

INCLUDEPATH += $$PWD/../../qt/Tools/OpenSSLv3/Win_x64/include
DEPENDPATH += $$PWD/../../qt/Tools/OpenSSLv3/Win_x64/include

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../qt/Tools/OpenSSLv3/Win_x64/release/ -llibssl
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../qt/Tools/OpenSSLv3/Win_x64/debug/ -llibssl

RESOURCES += \
    iconfile.qrc

