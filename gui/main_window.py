from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QFrame,
    QHeaderView
)

from PyQt6.QtGui import (
    QFont,
    QPixmap
)

from PyQt6.QtCore import Qt


class StatCard(QFrame):

    def __init__(self, title, value="0"):
        super().__init__()

        self.setFrameShape(
            QFrame.Shape.StyledPanel
        )

        layout = QVBoxLayout(self)

        self.value_label = QLabel(value)
        self.value_label.setFont(
            QFont("Segoe UI", 18, QFont.Weight.Bold)
        )

        self.title_label = QLabel(title)

        layout.addWidget(
            self.value_label,
            alignment=Qt.AlignmentFlag.AlignCenter
        )

        layout.addWidget(
            self.title_label,
            alignment=Qt.AlignmentFlag.AlignCenter
        )

    def set_value(self, value):
        self.value_label.setText(str(value))


class MainWindow(QWidget):

    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "Threat Intelligence Dashboard"
        )

        self.resize(1300, 850)

        self.setup_ui()

    def setup_ui(self):

        main_layout = QVBoxLayout(self)

        # ==================================
        # HEADER
        # ==================================

        header_layout = QHBoxLayout()

        self.logo_label = QLabel()

        pixmap = QPixmap(
            "assets/logo.png"
        )

        if not pixmap.isNull():

            self.logo_label.setPixmap(
                pixmap.scaled(
                    64,
                    64,
                    Qt.AspectRatioMode.KeepAspectRatio
                )
            )

        self.title_label = QLabel(
            "Threat Intelligence Dashboard"
        )

        self.title_label.setFont(
            QFont(
                "Segoe UI",
                20,
                QFont.Weight.Bold
            )
        )

        header_layout.addWidget(
            self.logo_label
        )

        header_layout.addWidget(
            self.title_label
        )

        header_layout.addStretch()

        main_layout.addLayout(
            header_layout
        )

        # ==================================
        # STATISTICS CARDS
        # ==================================

        cards_layout = QHBoxLayout()

        self.total_card = StatCard(
            "Total CVEs"
        )

        self.critical_card = StatCard(
            "Critical"
        )

        self.high_card = StatCard(
            "High"
        )

        self.ioc_card = StatCard(
            "IOCs"
        )

        cards_layout.addWidget(
            self.total_card
        )

        cards_layout.addWidget(
            self.critical_card
        )

        cards_layout.addWidget(
            self.high_card
        )

        cards_layout.addWidget(
            self.ioc_card
        )

        main_layout.addLayout(
            cards_layout
        )

        # ==================================
        # CONTROLS
        # ==================================

        controls_layout = QHBoxLayout()

        self.search_box = QLineEdit()

        self.search_box.setPlaceholderText(
            "Search CVE..."
        )

        self.severity_filter = QComboBox()

        self.severity_filter.addItems(
            [
                "All",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN"
            ]
        )

        self.refresh_btn = QPushButton(
            "Refresh Threat Feed"
        )

        controls_layout.addWidget(
            self.search_box
        )

        controls_layout.addWidget(
            self.severity_filter
        )

        controls_layout.addWidget(
            self.refresh_btn
        )

        main_layout.addLayout(
            controls_layout
        )

        # ==================================
        # STATUS LABEL
        # ==================================

        self.status_label = QLabel("Ready")

        self.status_label.setStyleSheet("""
            QLabel {
                padding: 8px;
                font-size: 12px;
                color: #00aa00;
            }
        """)

        main_layout.addWidget(
            self.status_label
        )

        # ==================================
        # CVE TABLE LABEL
        # ==================================

        cve_label = QLabel(
            "Threat Intelligence"
        )

        cve_label.setFont(
            QFont(
                "Segoe UI",
                12,
                QFont.Weight.Bold
            )
        )

        main_layout.addWidget(
            cve_label
        )

        # ==================================
        # CVE TABLE
        # ==================================

        self.cve_table = QTableWidget()

        self.cve_table.setColumnCount(
            4
        )

        self.cve_table.setHorizontalHeaderLabels(
            [
                "CVE",
                "Severity",
                "CVSS",
                "Description"
            ]
        )

        self.cve_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.cve_table.setAlternatingRowColors(
            True
        )

        main_layout.addWidget(
            self.cve_table
        )

        # ==================================
        # IOC LABEL
        # ==================================

        ioc_label = QLabel(
            "Indicators of Compromise (IOCs)"
        )

        ioc_label.setFont(
            QFont(
                "Segoe UI",
                12,
                QFont.Weight.Bold
            )
        )

        main_layout.addWidget(
            ioc_label
        )

        # ==================================
        # IOC TABLE
        # ==================================

        self.ioc_table = QTableWidget()

        self.ioc_table.setColumnCount(
            2
        )

        self.ioc_table.setHorizontalHeaderLabels(
            [
                "Type",
                "Value"
            ]
        )

        self.ioc_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.ioc_table.setAlternatingRowColors(
            True
        )

        main_layout.addWidget(
            self.ioc_table
        )

    # ==================================
    # LOAD CVE DATA
    # ==================================

    def load_threats(self, threats):

        self.cve_table.setRowCount(
            len(threats)
        )

        for row, threat in enumerate(threats):

            self.cve_table.setItem(
                row,
                0,
                QTableWidgetItem(
                    str(threat[1])
                )
            )

            self.cve_table.setItem(
                row,
                1,
                QTableWidgetItem(
                    str(threat[2])
                )
            )

            self.cve_table.setItem(
                row,
                2,
                QTableWidgetItem(
                    str(threat[3])
                )
            )

            self.cve_table.setItem(
                row,
                3,
                QTableWidgetItem(
                    str(threat[4])
                )
            )

    # ==================================
    # LOAD IOC DATA
    # ==================================

    def load_iocs(self, iocs):

        self.ioc_table.setRowCount(
            len(iocs)
        )

        for row, ioc in enumerate(iocs):

            self.ioc_table.setItem(
                row,
                0,
                QTableWidgetItem(
                    str(ioc[0])
                )
            )

            self.ioc_table.setItem(
                row,
                1,
                QTableWidgetItem(
                    str(ioc[1])
                )
            )

    # ==================================
    # UPDATE STATS
    # ==================================

    def update_stats(self, stats):

        self.total_card.set_value(
            stats["total"]
        )

        self.critical_card.set_value(
            stats["critical"]
        )

        self.high_card.set_value(
            stats["high"]
        )

        self.ioc_card.set_value(
            stats["iocs"]
        )