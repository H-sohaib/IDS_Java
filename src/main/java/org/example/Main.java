package org.example;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

public class Main extends Application {
    public static void main(String[] args) {
        // Launch the JavaFX application
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        // Create a label to display text
        Label label = new Label("Hello, JavaFX!");

        // Create a layout container (StackPane)
        StackPane root = new StackPane();
        root.getChildren().add(label);

        // Create a scene with the layout
        Scene scene = new Scene(root, 400, 300);

        // Set the scene and title on the primary stage
        primaryStage.setTitle("JavaFX Test");
        primaryStage.setScene(scene);

        // Show the stage
        primaryStage.show();
    }
}
