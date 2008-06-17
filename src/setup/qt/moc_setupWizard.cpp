/****************************************************************************
** Meta object code from reading C++ file 'setupWizard.h'
**
** Created: Sat Dec 22 17:16:20 2007
**      by: The Qt Meta Object Compiler version 59 (Qt 4.3.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "setupWizard.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'setupWizard.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 59
#error "This file was generated using the moc from 4.3.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

static const uint qt_meta_data_GSetupWizard[] = {

 // content:
       1,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   10, // methods
       0,    0, // properties
       0,    0, // enums/sets

 // slots: signature, parameters, type, tag, flags
      14,   13,   13,   13, 0x09,
      28,   13,   13,   13, 0x09,
      42,   13,   13,   13, 0x09,
      62,   57,   13,   13, 0x09,

       0        // eod
};

static const char qt_meta_stringdata_GSetupWizard[] = {
    "GSetupWizard\0\0nextClicked()\0prevClicked()\0"
    "abortClicked()\0link\0linkHandler(QUrl)\0"
};

const QMetaObject GSetupWizard::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_GSetupWizard,
      qt_meta_data_GSetupWizard, 0 }
};

const QMetaObject *GSetupWizard::metaObject() const
{
    return &staticMetaObject;
}

void *GSetupWizard::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_GSetupWizard))
	return static_cast<void*>(const_cast< GSetupWizard*>(this));
    return QDialog::qt_metacast(_clname);
}

int GSetupWizard::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: nextClicked(); break;
        case 1: prevClicked(); break;
        case 2: abortClicked(); break;
        case 3: linkHandler((*reinterpret_cast< const QUrl(*)>(_a[1]))); break;
        }
        _id -= 4;
    }
    return _id;
}
