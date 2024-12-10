# **NexusML API Quickstart Guide: From Task Creation to Prediction**

This guide provides a step-by-step walkthrough of using the NexusML API—from task creation to making predictions. By following these steps, you can define, train, and deploy custom AI models tailored to your needs. For more advanced usage or troubleshooting, refer to the NexusML API Documentation.

---

## **1. Create a Task**

Define the problem you want to solve by creating a **task**. Each task is based on a predefined template aligned with specific AI problems like classification, regression, or detection. Templates provide a blueprint for the task's schema.

### **Available Task Templates**
Each template corresponds to a specific AI problem type:

- **IMAGE_CLASSIFICATION (0):** Image classification
- **IMAGE_REGRESSION (1):** Image regression
- **OBJECT_DETECTION (2):** Object detection
- **OBJECT_SEGMENTATION (3):** Object segmentation
- **TEXT_CLASSIFICATION (4):** Text classification
- **TEXT_REGRESSION (5):** Text regression
- **AUDIO_CLASSIFICATION (6):** Audio classification
- **AUDIO_REGRESSION (7):** Audio regression
- **TABULAR_CLASSIFICATION (8):** Tabular classification
- **TABULAR_REGRESSION (9):** Tabular regression
- **MULTIMODAL_CLASSIFICATION (10):** Multimodal classification
- **MULTIMODAL_REGRESSION (11):** Multimodal regression

### Request
**POST** `/tasks`

Provide the task name, description, icon, and either a template or a type. Using templates is recommended, as they include pre-defined inputs and outputs. If opting for a type, you'll need to define inputs and outputs later.

```json
{
  "name": "<string>",
  "description": "<string>",
  "icon": "<string>",
  "template": "object_segmentation",
  "type": "<string>"
}

```
### Response

The response includes details about the created task, including the `id` or `uuid` for subsequent requests.
```json
{
  "address": "<string>",
  "domain": "<string>",
  "id": "<string>",
  "name": "<string>",
  "trn": "<string>",
  "uuid": "<string>",
  "logo": {
    "created_at": "<string>",
    "created_by": {
      "id": "<string>",
      "type": "user",
      "uuid": "<string>"
    },
    "filename": "<string>",
    "id": "<string>",
    "size": "<integer>",
    "uuid": "<string>",
    "download_url": "<string>",
    "upload_url": {
      "url": "<string>",
      "fields": {}
    }
  }
}
```

## 2. Add Inputs, Outputs and metadata

If you selected a template, inputs and outputs are predefined. Otherwise, you need to define the task schema, specifying:

- **Inputs**: Data you’ll provide (e.g., images, text, or audio).
- **Outputs**: Predictions the model will produce (e.g., categories or numerical values).
- **Metadata**: Additional descriptive information.

You can also add additional inputs and outputs at your discretion.

Defining the schema involves specifying the data types, constraints (e.g., required or nullable), 
and whether multiple values are supported. For example, you can define an input as an "image_file" to handle images 
or as "text" to process textual data. This step ensures the task schema is flexible yet precise enough to handle 
the requirements of your AI solution.

### Request

To add inputs, outputs, or metadata, the process remains the same; you only need to adjust the final direction you're pointing to.

**POST** `/task/<task_id>/schema/[input|outputs|metadata]`

The required data is the same for all three cases. The primary information you need to provide includes the name and the data type, 
which must be one of the following:
- Boolean (`boolean`)
- Integer (`integer`)
- Float (`float`)
- Text (`text`)
- Datetime (`datetime`)
- Category (`category`)
- Generic file (`generic_file`)
- Document file (`document_file`)
- Audio file (`audio_file`)
- Shape (`shape`)
- Slice (`slice`)

For multi-value data, you must specify a multi-value description, which should be one of the following options:
- Unordered (`unordered`): For data where the order does not matter, such as a list of tags or categories. 
- Ordered (`ordered`): For data where the order is significant, such as a sequence of steps or rankings.
- Time based (`time_based`): For data organized chronologically, such as a series of timestamps or events.

You must also specify whether the data is **nullable** or **required**. 

### Payload
```json
{
  "name": "<string>",
  "type": {
    "description": "Type of the values assigned: \"boolean\", \"integer\", \"float\", \"text\", \"datetime\", \"category\", \"generic_file\", \"document_file\", \"image_file\", \"video_file\", \"audio_file\", \"shape\", \"slice\""
  },
  "description": "<string>",
  "display_name": "<string>",
  "multi_value": {
    "description": "Allow multiple values: \"unordered\", \"ordered\", or \"time_based\" (index represents a time step).",
    "nullable": true
  },
  "nullable": "<boolean>",
  "required": "<boolean>"
}
```

## 3. Add Examples

Examples form the backbone of your task, as they are the actual data points used 
for training the model. Each example consists of values for all inputs and outputs
defined in the schema, along with optional metadata such as tags or labeling 
status. For instance, an example for an image classification task might include 
an image file as input and a label specifying the correct category. 
This step is crucial because the quality and diversity of examples directly 
impact the model's performance. By organizing examples into batches, 
you can efficiently upload large datasets.

    Note: Each task have a space limit (default 50mb). If you need more space contact with Neuraptic.

### Request

To add examples to your model make the following POST call:

**POST** `/examples`

The example must include all required inputs, outputs, and metadata as defined by the schema you selected or those you manually added.

For files and shapes, include the file or shape ID in the value description. If the example is labeled, also include the element's tags in this section.

### Payload
```json
{
  "batch": [
    {
      "values": [
        {
          "element": "<string>",
          "value": {
            "description": "Assigned value. For files and shapes, provide the ID.",
            "nullable": true
          }
        }
      ],
      "labeling_status": "labeled",
      "tags": {
        "elements": [
          {
            "element": "<string>",
            "tag": "<string>"
          }
        ]
      }
    }
  ]
}
```

## 3.1. Update files

If your task involves working with file-based inputs such as images, audio, 
or videos, you need to upload these files to the platform before adding
them as examples. This step ensures that the platform can access and process
the files during both training and prediction phases. Each file is assigned an ID,
which you reference in your schema and examples. Proper organization and uploading
of files are critical to maintain consistency and avoid data mismatches.

To accomplish this, you must first send the file metadata to the API. The API will then return a URL, which you will use to POST your file for storage.

### Request

o do this, first make a call to the following endpoint:

POST `/tasks/files`

In this POST request, you will send the file metadata. Specify what this file will be used for `ai_model`,
`input`, `output`, `metadata` or `picture`. Then define the type of file, the available options are `document`, `image`, `video`, and `audio`.

### Payload

```json
{
  "filename": "<string>",
  "size": "<integer>",
  "use_for": {
    "description": "File use: \"ai_model\" | \"input\" | \"output\" | \"metadata\" | \"picture\""
  },
  "type": {
    "description": "File type: \"document\" | \"image\" | \"video\" | \"audio\"",
    "nullable": true
  }
}
```

### Response

You will receive the file data in response, including the URL where you need to upload your file. Use this URL to POST the actual file for storage.
```json
{
  "created_at": "<string>",
  "created_by": {
    "id": "<string>",
    "type": "client",
    "uuid": "<string>"
  },
  "filename": "<string>",
  "id": "<string>",
  "size": "<integer>",
  "use_for": {
    "description": "File use: \"ai_model\" | \"input\" | \"output\" | \"metadata\" | \"picture\""
  },
  "uuid": "<string>",
  "download_url": "<string>",
  "type": {
    "description": "File type: \"document\" | \"image\" | \"video\" | \"audio\"",
    "nullable": true
  },
  "upload_url": {
    "url": "<string>",
    "fields": {}
  }
}
```

Under the `upload_url/url` field, you will find the URL where you need to upload your file. Use this URL to POST the file for storage.

## 4. Train the Model

Once your model is trained, you can use it to make predictions on new data. 
By providing inputs matching the schema, the model processes them and produces 
outputs according to the task’s defined structure. 
For example, in a text classification task, the model might predict a category 
like "positive" or "negative" for each input text. This step is where the model's
learned knowledge is applied to solve real-world problems. 


### Request

To initiate training, simply make the following call to the specific task:

POST `/task/<task_id>/train`

Replace `<task_id>` with the ID of the task you want to train.

    Note: Training may take some time. Ensure you have sufficient credits available if required.

## 5. Deployment

Once the model is trained, you must deploy it. You can choose to deploy the model to either a test or production environment, depending on your needs.

### Request

To deploy the model, first obtain the model ID, and then make the following call:

**POST** `task/deployment/<model_id>`

Replace `<model_id>` with the ID of the model you wish to deploy.

When deploying the model, you will need to specify the AI model and choose whether you want to deploy it to `production` or `testing`.

### Payload
```json
{
  "ai_model": "<string>",
  "environment": {
    "description": "Environment: \"production\" or \"testing\""
  }
}
```

## 5. Test the model

Before executing your model in production, you may want to test it. Use the models deployed to the testing environment for this purpose. Note that you can only test the most recent model uploaded to the testing environment.

Once you have tested the model and are satisfied with its performance, you can deploy it to production by following the steps outlined earlier.
### Request
To test a model make a call to:

POST `/tasks/<task_id>/test`

Replace `<task_id>` with the ID of the task for which you want to make the prediction test.


### Payload
```json
{
  "batch": [
    {
      "values": [
        {
          "element": "<string>",
          "value": {
            "description": "Input/Metadata value. For files, provide the ID",
            "nullable": true
          }
        }
      ],
      "targets": [
        {
          "element": "<string>",
          "value": {
            "description": "Target value. For files, provide the ID",
            "nullable": true
          }
        }
      ]
    }
  ]
}
```
### Response
You will receive the output defined in the schema, which will include the predicted values based on the input data you provided.

```json
{
  "ai_model": "<string>",
  "predictions": [
    {
      "outputs": [
        {
          "element": "<string>",
          "value": {
            "description": "Predicted value. Categorical values include category and scores:\n{\n\t\"category\": \"class_1\",\n\t\"scores\": {\n\t\t\"class_1\": <class_1_score>,\n\t\t\"class_2\": <class_2_score>\n\t}\n}",
            "nullable": true
          }
        }
      ]
    }
  ]
}
```
## 5. Make Predictions

To use the trained model in production for making predictions, simply send the input values. 
The current model in production will be used to generate predictions. If no trained model is available in production, an error will be returned.

### Request
To make a prediction, call the specific task prediction endpoint:

**POST** `/tasks/<task_id>/predict`

Replace `<task_id>` with the ID of the task for which you want to make the prediction.

To make the prediction, simply send all the required input data. 
Remember that when sending files, you need to send the file ID of the uploaded file to S3, not the file itself.

### Payload
```json
{
  "batch": [
    {
      "values": [
        {
          "element": "<string>",
          "value": {
            "description": "Input/Metadata value. For files, provide the ID.",
            "nullable": true
          }
        }
      ]
    }
  ]
}
```
### Response
You will receive the output defined in the schema, which will include the predicted values based on the input data you provided.

```json
{
  "ai_model": "<string>",
  "predictions": [
    {
      "outputs": [
        {
          "element": "<string>",
          "value": {
            "description": "Predicted value. Categorical values include category and scores:\n{\n\t\"category\": \"class_1\",\n\t\"scores\": {\n\t\t\"class_1\": <class_1_score>,\n\t\t\"class_2\": <class_2_score>\n\t}\n}",
            "nullable": true
          }
        }
      ]
    }
  ]
}
```
With this, you now have the foundational knowledge to initialize, train, and deploy an AI model on our platform. You are equipped to prepare your data, manage model training, handle file uploads, and make predictions once the model is deployed. Additionally, you understand how to work with different environments (test or production) and how to manage the model lifecycle, ensuring smooth transitions from training to deployment and real-time usage.