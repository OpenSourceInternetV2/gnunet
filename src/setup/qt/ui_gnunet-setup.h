/********************************************************************************
** Form generated from reading ui file 'gnunet-setup.ui'
**
** Created: Sat Jul 12 20:45:47 2008
**      by: Qt User Interface Compiler version 4.4.0
**
** WARNING! All changes made in this file will be lost when recompiling ui file!
********************************************************************************/

#ifndef UI_GNUNET_2D_SETUP_H
#define UI_GNUNET_2D_SETUP_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QCheckBox>
#include <QtGui/QComboBox>
#include <QtGui/QGroupBox>
#include <QtGui/QHBoxLayout>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QPushButton>
#include <QtGui/QRadioButton>
#include <QtGui/QSpacerItem>
#include <QtGui/QSpinBox>
#include <QtGui/QStackedWidget>
#include <QtGui/QTextBrowser>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE class Ui_SetupWizard
{
public:
  QVBoxLayout * vboxLayout;
  QStackedWidget *stackedWidget;
  QWidget *page;
  QVBoxLayout *vboxLayout1;
  QTextBrowser *htmlWelcome;
  QWidget *page_2;
  QVBoxLayout *vboxLayout2;
  QGroupBox *groupBox;
  QVBoxLayout *vboxLayout3;
  QLabel *label;
  QHBoxLayout *hboxLayout;
  QLabel *label_2;
  QSpacerItem *spacerItem;
  QComboBox *cmbIF;
  QSpacerItem *spacerItem1;
  QLabel *label_3;
  QHBoxLayout *hboxLayout1;
  QLabel *label_4;
  QSpacerItem *spacerItem2;
  QLineEdit *editIP;
  QSpacerItem *spacerItem3;
  QSpacerItem *spacerItem4;
  QWidget *page_3;
  QVBoxLayout *vboxLayout4;
  QGroupBox *groupBox_2;
  QVBoxLayout *vboxLayout5;
  QLabel *label_6;
  QHBoxLayout *hboxLayout2;
  QLabel *label_7;
  QSpacerItem *spacerItem5;
  QLineEdit *editUp;
  QHBoxLayout *hboxLayout3;
  QLabel *label_8;
  QSpacerItem *spacerItem6;
  QLineEdit *editDown;
  QSpacerItem *spacerItem7;
  QRadioButton *rbFull;
  QRadioButton *rbShared;
  QSpacerItem *spacerItem8;
  QLabel *label_9;
  QHBoxLayout *hboxLayout4;
  QLabel *label_10;
  QSpacerItem *spacerItem9;
  QSpinBox *spinCPU;
  QSpacerItem *spacerItem10;
  QWidget *page_4;
  QVBoxLayout *vboxLayout6;
  QGroupBox *groupBox_3;
  QVBoxLayout *vboxLayout7;
  QLabel *label_11;
  QHBoxLayout *hboxLayout5;
  QLabel *label_12;
  QSpacerItem *spacerItem11;
  QLineEdit *editUser;
  QHBoxLayout *hboxLayout6;
  QLabel *label_13;
  QSpacerItem *spacerItem12;
  QLineEdit *editGroup;
  QSpacerItem *spacerItem13;
  QWidget *page_5;
  QVBoxLayout *vboxLayout8;
  QGroupBox *groupBox_4;
  QVBoxLayout *vboxLayout9;
  QLabel *label_14;
  QCheckBox *cbMigr;
  QSpacerItem *spacerItem14;
  QLabel *label_15;
  QHBoxLayout *hboxLayout7;
  QLabel *label_16;
  QSpacerItem *spacerItem15;
  QSpinBox *spinQuota;
  QSpacerItem *spacerItem16;
  QCheckBox *cbAutostart;
  QSpacerItem *spacerItem17;
  QCheckBox *cbAutoshare;
  QSpacerItem *spacerItem18;
  QLabel *label_17;
  QCheckBox *cbEnhConfig;
  QSpacerItem *spacerItem19;
  QLabel *label_18;
  QCheckBox *cbGNUpdate;
  QSpacerItem *spacerItem20;
  QHBoxLayout *hboxLayout8;
  QSpacerItem *spacerItem21;
  QPushButton *pbPrev;
  QPushButton *pbNext;
  QPushButton *pbClose;

  void setupUi (QWidget * SetupWizard)
  {
    if (SetupWizard->objectName ().isEmpty ())
      SetupWizard->setObjectName (QString::fromUtf8 ("SetupWizard"));
    SetupWizard->resize (640, 483);
    const QIcon icon =
      QIcon (QString::fromUtf8 (":/pixmaps/gnunet-logo-small.png"));
    SetupWizard->setWindowIcon (icon);
    vboxLayout = new QVBoxLayout (SetupWizard);
#ifndef Q_OS_MAC
    vboxLayout->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout->setMargin (9);
#endif
    vboxLayout->setObjectName (QString::fromUtf8 ("vboxLayout"));
    stackedWidget = new QStackedWidget (SetupWizard);
    stackedWidget->setObjectName (QString::fromUtf8 ("stackedWidget"));
    page = new QWidget ();
    page->setObjectName (QString::fromUtf8 ("page"));
    vboxLayout1 = new QVBoxLayout (page);
#ifndef Q_OS_MAC
    vboxLayout1->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout1->setMargin (9);
#endif
    vboxLayout1->setObjectName (QString::fromUtf8 ("vboxLayout1"));
    htmlWelcome = new QTextBrowser (page);
    htmlWelcome->setObjectName (QString::fromUtf8 ("htmlWelcome"));

    vboxLayout1->addWidget (htmlWelcome);

    stackedWidget->addWidget (page);
    page_2 = new QWidget ();
    page_2->setObjectName (QString::fromUtf8 ("page_2"));
    vboxLayout2 = new QVBoxLayout (page_2);
#ifndef Q_OS_MAC
    vboxLayout2->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout2->setMargin (9);
#endif
    vboxLayout2->setObjectName (QString::fromUtf8 ("vboxLayout2"));
    groupBox = new QGroupBox (page_2);
    groupBox->setObjectName (QString::fromUtf8 ("groupBox"));
    vboxLayout3 = new QVBoxLayout (groupBox);
#ifndef Q_OS_MAC
    vboxLayout3->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout3->setMargin (9);
#endif
    vboxLayout3->setObjectName (QString::fromUtf8 ("vboxLayout3"));
    label = new QLabel (groupBox);
    label->setObjectName (QString::fromUtf8 ("label"));
    label->setFrameShape (QFrame::NoFrame);
    label->setWordWrap (true);

    vboxLayout3->addWidget (label);

    hboxLayout = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout->setSpacing (6);
#endif
    hboxLayout->setMargin (0);
    hboxLayout->setObjectName (QString::fromUtf8 ("hboxLayout"));
    label_2 = new QLabel (groupBox);
    label_2->setObjectName (QString::fromUtf8 ("label_2"));
    QFont font;
    font.setFamily (QString::fromUtf8 ("MS Shell Dlg 2"));
    font.setPointSize (8);
    font.setBold (true);
    font.setItalic (false);
    font.setUnderline (false);
    font.setWeight (75);
    font.setStrikeOut (false);
    label_2->setFont (font);

    hboxLayout->addWidget (label_2);

    spacerItem =
      new QSpacerItem (50, 20, QSizePolicy::Maximum, QSizePolicy::Minimum);

    hboxLayout->addItem (spacerItem);

    cmbIF = new QComboBox (groupBox);
    cmbIF->setObjectName (QString::fromUtf8 ("cmbIF"));
    cmbIF->setMinimumSize (QSize (420, 0));

    hboxLayout->addWidget (cmbIF);


    vboxLayout3->addLayout (hboxLayout);

    spacerItem1 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout3->addItem (spacerItem1);

    label_3 = new QLabel (groupBox);
    label_3->setObjectName (QString::fromUtf8 ("label_3"));
    label_3->setWordWrap (true);

    vboxLayout3->addWidget (label_3);

    hboxLayout1 = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout1->setSpacing (6);
#endif
    hboxLayout1->setMargin (0);
    hboxLayout1->setObjectName (QString::fromUtf8 ("hboxLayout1"));
    label_4 = new QLabel (groupBox);
    label_4->setObjectName (QString::fromUtf8 ("label_4"));
    label_4->setFont (font);

    hboxLayout1->addWidget (label_4);

    spacerItem2 =
      new QSpacerItem (50, 20, QSizePolicy::Maximum, QSizePolicy::Minimum);

    hboxLayout1->addItem (spacerItem2);

    editIP = new QLineEdit (groupBox);
    editIP->setObjectName (QString::fromUtf8 ("editIP"));
    editIP->setMinimumSize (QSize (420, 0));

    hboxLayout1->addWidget (editIP);


    vboxLayout3->addLayout (hboxLayout1);

    spacerItem3 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout3->addItem (spacerItem3);

    spacerItem4 =
      new QSpacerItem (20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

    vboxLayout3->addItem (spacerItem4);


    vboxLayout2->addWidget (groupBox);

    stackedWidget->addWidget (page_2);
    page_3 = new QWidget ();
    page_3->setObjectName (QString::fromUtf8 ("page_3"));
    vboxLayout4 = new QVBoxLayout (page_3);
#ifndef Q_OS_MAC
    vboxLayout4->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout4->setMargin (9);
#endif
    vboxLayout4->setObjectName (QString::fromUtf8 ("vboxLayout4"));
    groupBox_2 = new QGroupBox (page_3);
    groupBox_2->setObjectName (QString::fromUtf8 ("groupBox_2"));
    vboxLayout5 = new QVBoxLayout (groupBox_2);
#ifndef Q_OS_MAC
    vboxLayout5->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout5->setMargin (9);
#endif
    vboxLayout5->setObjectName (QString::fromUtf8 ("vboxLayout5"));
    label_6 = new QLabel (groupBox_2);
    label_6->setObjectName (QString::fromUtf8 ("label_6"));
    label_6->setWordWrap (true);

    vboxLayout5->addWidget (label_6);

    hboxLayout2 = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout2->setSpacing (6);
#endif
    hboxLayout2->setMargin (0);
    hboxLayout2->setObjectName (QString::fromUtf8 ("hboxLayout2"));
    label_7 = new QLabel (groupBox_2);
    label_7->setObjectName (QString::fromUtf8 ("label_7"));
    label_7->setFont (font);

    hboxLayout2->addWidget (label_7);

    spacerItem5 =
      new QSpacerItem (40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    hboxLayout2->addItem (spacerItem5);

    editUp = new QLineEdit (groupBox_2);
    editUp->setObjectName (QString::fromUtf8 ("editUp"));
    editUp->setMinimumSize (QSize (420, 0));

    hboxLayout2->addWidget (editUp);


    vboxLayout5->addLayout (hboxLayout2);

    hboxLayout3 = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout3->setSpacing (6);
#endif
    hboxLayout3->setMargin (0);
    hboxLayout3->setObjectName (QString::fromUtf8 ("hboxLayout3"));
    label_8 = new QLabel (groupBox_2);
    label_8->setObjectName (QString::fromUtf8 ("label_8"));
    label_8->setFont (font);

    hboxLayout3->addWidget (label_8);

    spacerItem6 =
      new QSpacerItem (50, 20, QSizePolicy::Maximum, QSizePolicy::Minimum);

    hboxLayout3->addItem (spacerItem6);

    editDown = new QLineEdit (groupBox_2);
    editDown->setObjectName (QString::fromUtf8 ("editDown"));
    editDown->setMinimumSize (QSize (420, 0));

    hboxLayout3->addWidget (editDown);


    vboxLayout5->addLayout (hboxLayout3);

    spacerItem7 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout5->addItem (spacerItem7);

    rbFull = new QRadioButton (groupBox_2);
    rbFull->setObjectName (QString::fromUtf8 ("rbFull"));
    rbFull->setFont (font);

    vboxLayout5->addWidget (rbFull);

    rbShared = new QRadioButton (groupBox_2);
    rbShared->setObjectName (QString::fromUtf8 ("rbShared"));
    rbShared->setFont (font);

    vboxLayout5->addWidget (rbShared);

    spacerItem8 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout5->addItem (spacerItem8);

    label_9 = new QLabel (groupBox_2);
    label_9->setObjectName (QString::fromUtf8 ("label_9"));
    label_9->setWordWrap (true);

    vboxLayout5->addWidget (label_9);

    hboxLayout4 = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout4->setSpacing (6);
#endif
    hboxLayout4->setMargin (0);
    hboxLayout4->setObjectName (QString::fromUtf8 ("hboxLayout4"));
    label_10 = new QLabel (groupBox_2);
    label_10->setObjectName (QString::fromUtf8 ("label_10"));
    label_10->setFont (font);

    hboxLayout4->addWidget (label_10);

    spacerItem9 =
      new QSpacerItem (50, 20, QSizePolicy::Maximum, QSizePolicy::Minimum);

    hboxLayout4->addItem (spacerItem9);

    spinCPU = new QSpinBox (groupBox_2);
    spinCPU->setObjectName (QString::fromUtf8 ("spinCPU"));
    spinCPU->setMinimumSize (QSize (420, 0));
    spinCPU->setMaximum (100);

    hboxLayout4->addWidget (spinCPU);


    vboxLayout5->addLayout (hboxLayout4);

    spacerItem10 =
      new QSpacerItem (20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

    vboxLayout5->addItem (spacerItem10);


    vboxLayout4->addWidget (groupBox_2);

    stackedWidget->addWidget (page_3);
    page_4 = new QWidget ();
    page_4->setObjectName (QString::fromUtf8 ("page_4"));
    vboxLayout6 = new QVBoxLayout (page_4);
#ifndef Q_OS_MAC
    vboxLayout6->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout6->setMargin (9);
#endif
    vboxLayout6->setObjectName (QString::fromUtf8 ("vboxLayout6"));
    groupBox_3 = new QGroupBox (page_4);
    groupBox_3->setObjectName (QString::fromUtf8 ("groupBox_3"));
    vboxLayout7 = new QVBoxLayout (groupBox_3);
#ifndef Q_OS_MAC
    vboxLayout7->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout7->setMargin (9);
#endif
    vboxLayout7->setObjectName (QString::fromUtf8 ("vboxLayout7"));
    label_11 = new QLabel (groupBox_3);
    label_11->setObjectName (QString::fromUtf8 ("label_11"));
    label_11->setWordWrap (true);

    vboxLayout7->addWidget (label_11);

    hboxLayout5 = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout5->setSpacing (6);
#endif
    hboxLayout5->setMargin (0);
    hboxLayout5->setObjectName (QString::fromUtf8 ("hboxLayout5"));
    label_12 = new QLabel (groupBox_3);
    label_12->setObjectName (QString::fromUtf8 ("label_12"));
    label_12->setFont (font);

    hboxLayout5->addWidget (label_12);

    spacerItem11 =
      new QSpacerItem (50, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    hboxLayout5->addItem (spacerItem11);

    editUser = new QLineEdit (groupBox_3);
    editUser->setObjectName (QString::fromUtf8 ("editUser"));
    editUser->setMinimumSize (QSize (440, 0));

    hboxLayout5->addWidget (editUser);


    vboxLayout7->addLayout (hboxLayout5);

    hboxLayout6 = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout6->setSpacing (6);
#endif
    hboxLayout6->setMargin (0);
    hboxLayout6->setObjectName (QString::fromUtf8 ("hboxLayout6"));
    label_13 = new QLabel (groupBox_3);
    label_13->setObjectName (QString::fromUtf8 ("label_13"));
    label_13->setFont (font);

    hboxLayout6->addWidget (label_13);

    spacerItem12 =
      new QSpacerItem (50, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    hboxLayout6->addItem (spacerItem12);

    editGroup = new QLineEdit (groupBox_3);
    editGroup->setObjectName (QString::fromUtf8 ("editGroup"));
    editGroup->setMinimumSize (QSize (440, 0));

    hboxLayout6->addWidget (editGroup);


    vboxLayout7->addLayout (hboxLayout6);

    spacerItem13 =
      new QSpacerItem (20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

    vboxLayout7->addItem (spacerItem13);


    vboxLayout6->addWidget (groupBox_3);

    stackedWidget->addWidget (page_4);
    page_5 = new QWidget ();
    page_5->setObjectName (QString::fromUtf8 ("page_5"));
    vboxLayout8 = new QVBoxLayout (page_5);
#ifndef Q_OS_MAC
    vboxLayout8->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout8->setMargin (9);
#endif
    vboxLayout8->setObjectName (QString::fromUtf8 ("vboxLayout8"));
    groupBox_4 = new QGroupBox (page_5);
    groupBox_4->setObjectName (QString::fromUtf8 ("groupBox_4"));
    vboxLayout9 = new QVBoxLayout (groupBox_4);
#ifndef Q_OS_MAC
    vboxLayout9->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout9->setMargin (9);
#endif
    vboxLayout9->setObjectName (QString::fromUtf8 ("vboxLayout9"));
    label_14 = new QLabel (groupBox_4);
    label_14->setObjectName (QString::fromUtf8 ("label_14"));
    label_14->setWordWrap (true);

    vboxLayout9->addWidget (label_14);

    cbMigr = new QCheckBox (groupBox_4);
    cbMigr->setObjectName (QString::fromUtf8 ("cbMigr"));
    cbMigr->setFont (font);

    vboxLayout9->addWidget (cbMigr);

    spacerItem14 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout9->addItem (spacerItem14);

    label_15 = new QLabel (groupBox_4);
    label_15->setObjectName (QString::fromUtf8 ("label_15"));
    label_15->setWordWrap (true);

    vboxLayout9->addWidget (label_15);

    hboxLayout7 = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout7->setSpacing (6);
#endif
    hboxLayout7->setMargin (0);
    hboxLayout7->setObjectName (QString::fromUtf8 ("hboxLayout7"));
    label_16 = new QLabel (groupBox_4);
    label_16->setObjectName (QString::fromUtf8 ("label_16"));
    label_16->setFont (font);

    hboxLayout7->addWidget (label_16);

    spacerItem15 =
      new QSpacerItem (50, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    hboxLayout7->addItem (spacerItem15);

    spinQuota = new QSpinBox (groupBox_4);
    spinQuota->setObjectName (QString::fromUtf8 ("spinQuota"));
    spinQuota->setMinimumSize (QSize (370, 0));
    spinQuota->setMaximum (1000000);

    hboxLayout7->addWidget (spinQuota);


    vboxLayout9->addLayout (hboxLayout7);

    spacerItem16 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout9->addItem (spacerItem16);

    cbAutostart = new QCheckBox (groupBox_4);
    cbAutostart->setObjectName (QString::fromUtf8 ("cbAutostart"));
    QFont font1;
    font1.setBold (true);
    font1.setWeight (75);
    cbAutostart->setFont (font1);

    vboxLayout9->addWidget (cbAutostart);

    spacerItem17 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout9->addItem (spacerItem17);

    cbAutoshare = new QCheckBox (groupBox_4);
    cbAutoshare->setObjectName (QString::fromUtf8 ("cbAutoshare"));
    cbAutoshare->setEnabled (false);
    cbAutoshare->setFont (font1);

    vboxLayout9->addWidget (cbAutoshare);

    spacerItem18 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout9->addItem (spacerItem18);

    label_17 = new QLabel (groupBox_4);
    label_17->setObjectName (QString::fromUtf8 ("label_17"));
    label_17->setWordWrap (true);

    vboxLayout9->addWidget (label_17);

    cbEnhConfig = new QCheckBox (groupBox_4);
    cbEnhConfig->setObjectName (QString::fromUtf8 ("cbEnhConfig"));
    cbEnhConfig->setEnabled (false);
    cbEnhConfig->setFont (font);

    vboxLayout9->addWidget (cbEnhConfig);

    spacerItem19 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

    vboxLayout9->addItem (spacerItem19);

    label_18 = new QLabel (groupBox_4);
    label_18->setObjectName (QString::fromUtf8 ("label_18"));
    label_18->setWordWrap (true);

    vboxLayout9->addWidget (label_18);

    cbGNUpdate = new QCheckBox (groupBox_4);
    cbGNUpdate->setObjectName (QString::fromUtf8 ("cbGNUpdate"));
    cbGNUpdate->setFont (font);
    cbGNUpdate->setChecked (true);

    vboxLayout9->addWidget (cbGNUpdate);

    spacerItem20 =
      new QSpacerItem (20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

    vboxLayout9->addItem (spacerItem20);


    vboxLayout8->addWidget (groupBox_4);

    stackedWidget->addWidget (page_5);

    vboxLayout->addWidget (stackedWidget);

    hboxLayout8 = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout8->setSpacing (6);
#endif
    hboxLayout8->setMargin (0);
    hboxLayout8->setObjectName (QString::fromUtf8 ("hboxLayout8"));
    spacerItem21 =
      new QSpacerItem (40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    hboxLayout8->addItem (spacerItem21);

    pbPrev = new QPushButton (SetupWizard);
    pbPrev->setObjectName (QString::fromUtf8 ("pbPrev"));
    pbPrev->setMinimumSize (QSize (75, 0));
    const QIcon icon1 =
      QIcon (QString::fromUtf8 (":/pixmaps/go-previous.png"));
    pbPrev->setIcon (icon1);
    pbPrev->setIconSize (QSize (22, 22));

    hboxLayout8->addWidget (pbPrev);

    pbNext = new QPushButton (SetupWizard);
    pbNext->setObjectName (QString::fromUtf8 ("pbNext"));
    pbNext->setMinimumSize (QSize (75, 0));
    const QIcon icon2 = QIcon (QString::fromUtf8 (":/pixmaps/go-next.png"));
    pbNext->setIcon (icon2);
    pbNext->setIconSize (QSize (22, 22));

    hboxLayout8->addWidget (pbNext);

    pbClose = new QPushButton (SetupWizard);
    pbClose->setObjectName (QString::fromUtf8 ("pbClose"));
    pbClose->setMinimumSize (QSize (75, 0));
    const QIcon icon3 = QIcon (QString::fromUtf8 (":/pixmaps/close.png"));
    pbClose->setIcon (icon3);
    pbClose->setIconSize (QSize (22, 22));

    hboxLayout8->addWidget (pbClose);


    vboxLayout->addLayout (hboxLayout8);


    retranslateUi (SetupWizard);

    stackedWidget->setCurrentIndex (0);


    QMetaObject::connectSlotsByName (SetupWizard);
  }                             // setupUi

  void retranslateUi (QWidget * SetupWizard)
  {
    SetupWizard->
      setWindowTitle (QApplication::
                      translate ("SetupWizard", "GNUnet setup", 0,
                                 QApplication::UnicodeUTF8));
    groupBox->
      setTitle (QApplication::
                translate ("SetupWizard",
                           "Network connection - enter information about your network connection here",
                           0, QApplication::UnicodeUTF8));
    label->
      setText (QApplication::
               translate ("SetupWizard",
                          "Choose the device that connects your computer to the internet. This is usually a modem, an ISDN card or a network card in case you are using DSL.",
                          0, QApplication::UnicodeUTF8));
    label_2->
      setText (QApplication::
               translate ("SetupWizard", "Network interface:", 0,
                          QApplication::UnicodeUTF8));
    label_3->
      setText (QApplication::
               translate ("SetupWizard",
                          "If your provider always assigns the same IP-Address to you (a \"static\" IP-Address), enter it into this field. If your IP-Address changes every now and then (\"dynamic\" IP-Address) but there's a hostname that always points to your actual IP-Address (\"Dynamic DNS\"), you can also enter it here.\n"
                          "If in doubt, leave the field empty. GNUnet will then try to determine your IP-Address.",
                          0, QApplication::UnicodeUTF8));
    label_4->
      setText (QApplication::
               translate ("SetupWizard", "IP-Address/Hostname:", 0,
                          QApplication::UnicodeUTF8));
    groupBox_2->
      setTitle (QApplication::
                translate ("SetupWizard",
                           "Load limitation - limit GNUnet's ressource usage here",
                           0, QApplication::UnicodeUTF8));
    label_6->
      setText (QApplication::
               translate ("SetupWizard",
                          "This is how much data may be sent per second. If you have a flatrate you can set it to the maximum speed of your internet connection.",
                          0, QApplication::UnicodeUTF8));
    label_7->
      setText (QApplication::
               translate ("SetupWizard", "Upstream (Bytes/s):", 0,
                          QApplication::UnicodeUTF8));
    label_8->
      setText (QApplication::
               translate ("SetupWizard", "Downstream (Bytes/s):", 0,
                          QApplication::UnicodeUTF8));
    rbFull->
      setText (QApplication::
               translate ("SetupWizard", "Use denoted bandwidth for GNUnet",
                          0, QApplication::UnicodeUTF8));
    rbShared->
      setText (QApplication::
               translate ("SetupWizard",
                          "Share denoted bandwidth with other applications",
                          0, QApplication::UnicodeUTF8));
    label_9->
      setText (QApplication::
               translate ("SetupWizard",
                          "Enter the percentage of processor time GNUnet is allowed to use here.",
                          0, QApplication::UnicodeUTF8));
    label_10->
      setText (QApplication::
               translate ("SetupWizard", "Maximum CPU usage (%):", 0,
                          QApplication::UnicodeUTF8));
    groupBox_3->
      setTitle (QApplication::
                translate ("SetupWizard",
                           "Security settings - specify the user and the group owning the GNUnet service here",
                           0, QApplication::UnicodeUTF8));
    label_11->
      setText (QApplication::
               translate ("SetupWizard",
                          "For security reasons, it is a good idea to let this setup create a new user account and a new group under which the GNUnet service is started at system startup.\n"
                          "\n"
                          "However, GNUnet may not be able to access files other than its own. This includes files you want to publish in GNUnet. You will have to grant read permissions to the user specified below.\n"
                          "\n"
                          "Leave the fields empty to run GNUnet with system privileges.",
                          0, QApplication::UnicodeUTF8));
    label_12->
      setText (QApplication::
               translate ("SetupWizard", "User account:", 0,
                          QApplication::UnicodeUTF8));
    label_13->
      setText (QApplication::
               translate ("SetupWizard", "Group:", 0,
                          QApplication::UnicodeUTF8));
    groupBox_4->
      setTitle (QApplication::
                translate ("SetupWizard", "Other settings", 0,
                           QApplication::UnicodeUTF8));
    label_14->
      setText (QApplication::
               translate ("SetupWizard",
                          "GNUnet is able to store data from other peers in your datastore. This is useful if an adversary has access to your inserted content and you need to deny that the content is yours. With \"content migration\" on, the content could have \"migrated\" over the internet to your node without your knowledge.\n"
                          "It also helps to spread popular content over different peers to enhance availability.",
                          0, QApplication::UnicodeUTF8));
    cbMigr->
      setText (QApplication::
               translate ("SetupWizard", "Store migrated content", 0,
                          QApplication::UnicodeUTF8));
    label_15->
      setText (QApplication::
               translate ("SetupWizard",
                          "The GNUnet datastore contains all data that GNUnet generates (index data, inserted and migrated content). Its maximum size can be specified below.",
                          0, QApplication::UnicodeUTF8));
    label_16->
      setText (QApplication::
               translate ("SetupWizard", "Maximum datastore size (MB):", 0,
                          QApplication::UnicodeUTF8));
    cbAutostart->
      setText (QApplication::
               translate ("SetupWizard",
                          "Start GNUnet background process on computer startup",
                          0, QApplication::UnicodeUTF8));
    cbAutoshare->
      setText (QApplication::
               translate ("SetupWizard",
                          "Start republication process on computer startup",
                          0, QApplication::UnicodeUTF8));
    label_17->
      setText (QApplication::
               translate ("SetupWizard",
                          "If you are an experienced user, you may want to tweak your GNUnet installation using the enhanced configurator.",
                          0, QApplication::UnicodeUTF8));
    cbEnhConfig->
      setText (QApplication::
               translate ("SetupWizard", "Open the enhanced configurator", 0,
                          QApplication::UnicodeUTF8));
    label_18->
      setText (QApplication::
               translate ("SetupWizard",
                          "After changing the configuration and/or updating GNUnet, it is sometimes required to run gnunet-update to update internal data structures. Depending on the changes made, this may take some time.",
                          0, QApplication::UnicodeUTF8));
    cbGNUpdate->
      setText (QApplication::
               translate ("SetupWizard", "Run gnunet-update", 0,
                          QApplication::UnicodeUTF8));
    pbPrev->
      setText (QApplication::
               translate ("SetupWizard", "Previous", 0,
                          QApplication::UnicodeUTF8));
    pbNext->
      setText (QApplication::
               translate ("SetupWizard", "Next", 0,
                          QApplication::UnicodeUTF8));
    pbClose->
      setText (QApplication::
               translate ("SetupWizard", "Close", 0,
                          QApplication::UnicodeUTF8));
    Q_UNUSED (SetupWizard);
  }                             // retranslateUi

};

namespace Ui
{
  class SetupWizard:public Ui_SetupWizard
  {
  };
}                               // namespace Ui

QT_END_NAMESPACE
#endif                          // UI_GNUNET_2D_SETUP_H
