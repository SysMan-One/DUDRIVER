TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += debug_and_release
CONFIG += static

SOURCES += \
    dudriver.c

LINEXVER=$$(LINEXVER) #export LINEXVER=$(uname -r)


INCLUDEPATH	+=./
INCLUDEPATH	+=/usr/src/linux-headers-$$LINEXVER/arch/x86/include/
INCLUDEPATH	+=/usr/include/
INCLUDEPATH	+=/usr/src/linux-headers-$$LINEXVER/include/
INCLUDEPATH	+=/usr/src/linux-headers-$$LINEXVER/arch/x86/include/

DEFINES		+= CONFIG_BLOCK

LIBS		+=

CONFIG (debug, debug|release) {
        CONFIG	+= warn_off
        DEFINES	+= _DEBUG=1 __TRACE__=1

} else {
        #CONFIG	+= warn_off
        DEFINES	+= _DEBUG=1 __TRACE__=1
}
