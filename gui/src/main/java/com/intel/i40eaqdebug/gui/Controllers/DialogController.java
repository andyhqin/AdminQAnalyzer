package com.intel.i40eaqdebug.gui.Controllers;

import com.intel.i40eaqdebug.api.APIEntryPoint;
import com.intel.i40eaqdebug.api.logs.LogEntry;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.LoadException;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.chart.AreaChart;
import javafx.scene.control.*;
import javafx.scene.layout.Pane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.util.Queue;

public class DialogController {
    @FXML
    private Parent Dialog;
    @FXML
    private Button CancelButton;
    @FXML
    private TextArea TextBox;
    @FXML
    private String Text;

    private boolean DisableCancel = false;

    //There's no real way to handle this error other then to crash...
    public static void CreateDialog(String Title, String Body, boolean HideCancel){
        FXMLLoader loader = new FXMLLoader(DialogController.class.getResource("/BasicDialog.fxml"));

        loader.setController(new DialogController(Body, HideCancel));


        Stage stage = new Stage();
        stage.setTitle(Title);

        try {
            stage.setScene(new Scene((Pane) loader.load(), 350, 150));
        } catch (Exception e) {
            //TODO: try to rebuild the controller manually here.
            return;
        }
        stage.setResizable(false);

        stage.show();
    }

    public DialogController(String BodyText, boolean HideButton) {
        Text = BodyText;
        DisableCancel = HideButton;
    }

    public DialogController() {}

    public void initialize(){
        TextBox.setText(Text);

        if (DisableCancel) {
            CancelButton.setVisible(false);
        }
    }

    @FXML
    public void Cancel() {
        Dialog.getScene().getWindow().hide();
    }

    @FXML
    public void Ok() {
        //TODO: return something form controller.
        Dialog.getScene().getWindow().hide();
    }
}
