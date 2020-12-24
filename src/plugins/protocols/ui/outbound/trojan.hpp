#pragma once

#include "CommonTypes.hpp"
#include "QvGUIPluginInterface.hpp"
#include "ui_trojan.h"

class TrojanOutboundEditor
    : public Qv2rayPlugin::QvPluginEditor
    , private Ui::trojanOutEditor
{
    Q_OBJECT

  public:
    explicit TrojanOutboundEditor(QWidget *parent = nullptr);

    void SetHostAddress(const QString &addr, int port) override
    {
        trojan.address = addr;
        trojan.port = port;
    };
    QPair<QString, int> GetHostAddress() const override
    {
        return { trojan.address, trojan.port };
    };

    void SetContent(const QJsonObject &content) override
    {
        PLUGIN_EDITOR_LOADING_SCOPE({
            if (content["servers"].toArray().isEmpty())
                content["servers"] = QJsonArray{ QJsonObject{} };
            // Trojan Configs
            trojan = TrojanServerObject::fromJson(content["servers"].toArray().first().toObject());
            trojan_passwordTxt->setText(trojan.password);
        })
    }
    const QJsonObject GetContent() const override
    {
        auto result = content;
        QJsonArray servers;
        servers.append(trojan.toJson());
        result.insert("servers", servers);
        return result;
    }

  protected:
    void changeEvent(QEvent *e) override;

  private slots:
    void on_trojan_passwordTxt_textEdited(const QString &arg1);

  private:
    TrojanServerObject trojan;
};
