# **NexusML API Quickstart Guide: From Task Creation to Prediction**

This guide provided a step-by-step walkthrough of using the NexusML API—from task creation to making predictions. By following these steps, you can define, train, and deploy custom AI models tailored to your specific needs. For more advanced usage or troubleshooting, refer to the NexusML API Documentation. Happy modeling!

---

## **1. Create a Task**

The first step is to define the problem you want to solve by creating a **task**. Each **task** is based on a predefined template that aligns with specific types of AI problems, such as classification, regression, or detection. These templates act as blueprints for structuring your task's schema. For example, a task using the "IMAGE_CLASSIFICATION" template would be structured to accept labeled image data and produce category predictions. When creating a task, you also define its metadata, including a name, description, and an optional icon to help organize tasks within your system.

### **Available Task Templates**
Each task template corresponds to a specific type of problem:

- **IMAGE_CLASSIFICATION (0):** Image classification.
- **IMAGE_REGRESSION (1):** Image regression.
- **OBJECT_DETECTION (2):** Object detection.
- **OBJECT_SEGMENTATION (3):** Object segmentation.
- **TEXT_CLASSIFICATION (4):** Text classification.
- **TEXT_REGRESSION (5):** Text regression.
- **AUDIO_CLASSIFICATION (6):** Audio classification.
- **AUDIO_REGRESSION (7):** Audio regression.
- **TABULAR_CLASSIFICATION (8):** Tabular classification.
- **TABULAR_REGRESSION (9):** Tabular regression.
- **MULTIMODAL_CLASSIFICATION (10):** Multimodal classification.
- **MULTIMODAL_REGRESSION (11):** Multimodal regression.

### Request
To make the request use:

**POST** `/tasks`

You will have to provide a name, a description of the model, an icon and a selected template or a type.
Templates are the usual way to go, it includes the basic inputs and outputs for each case. If you want to create a
task outside the templates or you need to create the task and later add the inputs and outputs you can choose send the
type instead of a template.

Note: All templates have a defined type. Do not send a template and a type or the request will fail.
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

The response contains details about the created task. Use the id or uuid for subsequent requests.

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

After creating a task, if you chose a template inputs and outputs are already defined. You can add metadata to the task.
In case you only chose a type, you need to specify its schema now, which consists of inputs and outputs. 
Inputs are the data you’ll provide to the model (e.g., images, text, or audio), 
while outputs represent what the model will predict (e.g., categories, numerical values, or structured outputs). 
Defining the schema involves specifying the data types, constraints (e.g., required or nullable), 
and whether multiple values are supported. For example, you can define an input as an "image_file" to handle images 
or as "text" to process textual data. This step ensures the task schema is flexible yet precise enough to handle 
the requirements of your AI solution.

### Request

To add input output or metadatada the request is the same, only changing the las direction you are pointing to.

POST /task/<task_id>/schema/[input|outputs|metadata]

The data needed it is also the same in the three cases. The main data you need to send is the name,
the type of data that must be one of the following list:
- Boolean (boolean)
- Integer (integer)
- Float (float)
- Text (text)
- Datetime (datetime)
- Category (category)
- Generic file (generic_file)
- Document file (document_file)
- Audio file (audio_file)
- Shape (shape)
- Slice (slice)

In case of multi value data, multivalue description must be one fof the folling options:
- Unordered (unordered): For unordered data like, 
- Ordered (ordered): For ordered data like,
- Time based (time_based): For time based data like,

You have also define if this data is nullable or required.

### Payload Example
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
Each task have a space limit (default 50mb). If you need more space contact with 
### Request

To add examples to your model you have to make this request:

POST `/examples`

The example will require to have all the required inputs, outputs and metadata the schema you
chose define or the ones you added manually.

For files and shapes you will add the file or shape ID in the value description. If the example
is labeled, add the elements tags here too.

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

To do that you will
have to first send the file metadata to the API. Then the API will send you a URL where
you will POST your file to be saved.

### Request

To do this first make a call to:

POST `/tasks/files`

In this post you will send the file metadata. Specify what this file will be used for `ai_model`,
`input`, `output`, `metadata` or `picture`. Then define the type of file, the available options are `document`, `image`, `video`, and `audio`

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

You will reciece the file data, including the URL where you will have to upload your file

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

Under `upload_url/url` you will  find the URL to upload your file.

## 4. Train the Model

Once your model is trained, you can use it to make predictions on new data. 
By providing inputs matching the schema, the model processes them and produces 
outputs according to the task’s defined structure. 
For example, in a text classification task, the model might predict a category 
like "positive" or "negative" for each input text. This step is where the model's
learned knowledge is applied to solve real-world problems. 
You can batch predictions to process multiple inputs efficiently in a single 
API call.

### Request

To make a train just make this call to a specific task:

POST `/task/<task_id>/train`

    Note: Training may take time. TO ENAIA: Ensure you have sufficient credits if required.

## 5. Deployment

Once the model is trained, you must deploy it. You can deploy the model to test or production.

### Request

To deploy the model get the model ID and then call:

**POST** `task/deployment/<model_id>`

You will have to specify the ai model and chose if you want to deploy to `production` or `testing`.

### Payload
```json
{
  "ai_model": "<string>",
  "environment": {
    "description": "Environment: \"production\" or \"testing\""
  }
}
```
## 5. Make Predictions

Use the trained model in production to make predictions. You just need to send the input values and the current
model in production will be used. If there is no trained model in production aan error will be returned.

### Request
To make a prediction call the specific task prediction endpoint:

**POST** `/tasks/<task_id>/predict`

Just send all the required input data. Remember that to send files you have to send the file ID of the 
uploaded file to S3 and not the file itself.
### Payload
```
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
You will receive the output defined in the schema with the predicted values.
```
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
