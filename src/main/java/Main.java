import javafx.application.Application;
import javafx.stage.Stage;
import com.ids.ui.NetworkMonitorUI;

public class Main extends Application {
    public static void main(String[] args) {
        // Launch the JavaFX application
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        // Create an instance of the NetworkMonitorUI class
        NetworkMonitorUI networkMonitorUI = new NetworkMonitorUI();

        // Initialize and start the UI
        networkMonitorUI.start(primaryStage);
    }
}