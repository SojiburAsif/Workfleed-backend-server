const express = require('express');
const cors = require('cors');
require('dotenv').config();
const PORT = process.env.PORT || 5000;
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const app = express();

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'https://resonant-syrniki-b1e2dc.netlify.app'],
  credentials: true
}));
app.use(express.json());

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')


const serviceAccount = JSON.parse(decoded);


admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@project-server.fv9q8on.mongodb.net/?retryWrites=true&w=majority&appName=Project-server`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    const workCollection = client.db('myDatabase').collection('works');
    const usersCollection = client.db('myDatabase').collection('user');
    const payrollCollection = client.db('myDatabase').collection('payment');
    const ReviewCollection = client.db('myDatabase').collection('Reviews');

    // Firebase Token Verify Middleware
    const verifyFBToken = (req, res, next) => {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ message: 'Unauthorized: No token provided' });
      }

      const token = authHeader.split(' ')[1];

      admin
        .auth()
        .verifyIdToken(token)
        .then((decodedToken) => {
          req.user = decodedToken;
          next();
        })
        .catch((error) => {
          console.error('Firebase token verification failed:', error.message);
          res.status(403).send({ message: 'Forbidden: Invalid token' });
        });
    };

    // Admin Role Verify Middleware
    const verifyAdmin = async (req, res, next) => {
      const userEmail = req.user.email;

      try {
        const user = await usersCollection.findOne({ email: userEmail });
        if (user && user.role === 'admin') {
          next();
        } else {
          res.status(403).json({ message: 'Forbidden: Admins only' });
        }
      } catch (error) {
        console.error('Error in verifyAdmin middleware:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    };


    // Admin-only route example
    app.get('/admin/secret-data', verifyFBToken, verifyAdmin, (req, res) => {
      res.send({ secret: "This is admin only data." });
    });

    // --- WorkSheet APIs --- 


    app.get('/works', verifyFBToken, async (req, res) => {
      try {
        const { email, month } = req.query;
        const query = {};

        if (email) {
          query.userEmail = email;
        }

        if (month) {
          const regex = new RegExp(`^\\d{4}-${month}-\\d{2}$`);
          query.date = { $regex: regex };
        }

        const works = await workCollection.find(query).toArray();
        res.send(works);
      } catch (err) {
        console.error('Error fetching filtered works:', err);
        res.status(500).send({ message: 'Server error while fetching work data' });
      }
    });

    app.post('/work', (req, res) => {
      const newWork = req.body;

      if (!newWork.task || !newWork.hours || !newWork.date || !newWork.userEmail) {
        return res.status(400).send({ message: 'Missing required fields' });
      }

      workCollection.insertOne(newWork)
        .then(result => res.send({ _id: result.insertedId, ...newWork }))
        .catch(err => {
          console.error("Insert failed:", err);
          res.status(500).send({ message: 'Server error while adding work' });
        });
    });

    app.put('/works/:id', verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const updatedData = { ...req.body };
      delete updatedData._id;

      try {
        const result = await workCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount > 0) {
          res.send({ message: 'Updated successfully' });
        } else {
          res.status(404).send({ message: 'Work not found' });
        }
      } catch (err) {
        console.error('PUT error:', err);
        res.status(500).send(err);
      }
    });

    app.delete('/works/:id', (req, res) => {
      const id = req.params.id;
      workCollection.deleteOne({ _id: new ObjectId(id) })
        .then(result => {
          if (result.deletedCount > 0) res.send({ message: 'Deleted successfully' });
          else res.status(404).send({ message: 'Work not found' });
        })
        .catch(err => res.status(500).send(err));
    });

    // user data
    app.post('/users', async (req, res) => {
      try {
        const user = req.body;

        if (!user?.email || !user?.name) {
          return res.status(400).json({ message: 'Invalid user data' });
        }

        const existing = await usersCollection.findOne({ email: user.email });

        if (existing) {
          return res.status(200).json({
            message: 'User already exists',
            user: existing,
          });
        }

        const result = await usersCollection.insertOne(user);

        if (result.insertedId) {
          return res.status(201).json({
            message: 'User registered successfully',
            insertedId: result.insertedId,
          });
        } else {
          return res.status(500).json({ message: 'Failed to register user' });
        }

      } catch (error) {
        console.error('User Registration Error:', error.message);
        return res.status(500).json({ message: 'Internal server error' });
      }
    });

    app.get('/users', verifyFBToken, async (req, res) => {
      try {
        const { verified } = req.query; // 'true' বা 'false' বা undefined
        let query = {};

        if (verified === 'true') {
          query.isVerified = true;
        } else if (verified === 'false') {
          query.isVerified = false;
        }

        const users = await usersCollection.find(query).toArray();
        res.send(users);
      } catch (error) {
        res.status(500).send({ error: 'Failed to fetch users' });
      }
    });

    app.get('/users/:id', verifyFBToken, async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: 'Invalid user ID' });
      }

      try {
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });

        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }

        res.status(200).send(user);
      } catch (error) {
        console.error("Error fetching single user:", error.message);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    app.put('/users/:id', verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updateData = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid user ID' });
        }

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.modifiedCount > 0) {
          return res.status(200).json({ message: 'User updated successfully' });
        } else {
          return res.status(404).json({ message: 'User not found or no changes made' });
        }
      } catch (error) {
        console.error('Update User Error:', error.message);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    app.put('/users/fire/:id', verifyFBToken, async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid user ID' });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { fired: true } }
        );

        if (result.modifiedCount > 0) {
          res.status(200).json({ message: 'User fired successfully' });
        } else {
          res.status(404).json({ message: 'User not found or already fired' });
        }
      } catch (error) {
        console.error('Fire user error:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });
    app.put('/users/unfire/:id', verifyFBToken, async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid user ID' });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { fired: false } }
        );

        if (result.modifiedCount > 0) {
          res.status(200).json({ message: 'User reactivated (unfired) successfully' });
        } else {
          res.status(404).json({ message: 'User not found or already unfired' });
        }
      } catch (error) {
        console.error('Unfire user error:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    })

    app.put('/users/make-hr/:id', verifyFBToken, async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid user ID' });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id), role: 'employee' },
          { $set: { role: 'HR' } }
        );
// sad
        if (result.modifiedCount > 0) {
          res.status(200).json({ message: 'User promoted to HR' });
        } else {
          res.status(404).json({ message: 'User not found or already HR/Admin' });
        }
      } catch (error) {
        console.error('Make HR error:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    app.put('/users/salary/:id', async (req, res) => {
      const id = req.params.id;
      const { salary } = req.body;

      if (!ObjectId.isValid(id) || typeof salary !== 'number') {
        return res.status(400).json({ message: 'Invalid ID or salary' });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { salary } }
        );

        if (result.modifiedCount > 0) {
          res.status(200).json({ message: 'Salary updated successfully' });
        } else {
          res.status(404).json({ message: 'User not found or no changes made' });
        }
      } catch (error) {
        console.error('Salary update error:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    app.put('/users/make-employee/:id', async (req, res) => {
      const id = req.params.id;
      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role: 'employee' } }
      );
      res.send(result);
    });

    app.patch('/users/make-admin/:id', verifyAdmin, async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid user ID' });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id), role: { $in: ['employee', 'HR'] } },
          { $set: { role: 'admin' } }
        );

        if (result.modifiedCount > 0) {
          res.status(200).json({ message: 'User promoted to admin' });
        } else {
          res.status(404).json({ message: 'User not found or already admin' });
        }
      } catch (error) {
        console.error('Make admin error:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });
    // fire
    app.put('/users/rehire/:id', async (req, res) => {
      const userId = req.params.id;

      // Validate ObjectId
      if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ message: 'Invalid user ID' });
      }

      try {
        // Fired ফিল্ড false করে আপডেট
        const updatedUser = await User.findByIdAndUpdate(
          userId,
          { fired: false },
          { new: true }
        );

        if (!updatedUser) {
          return res.status(404).json({ message: 'User not found' });
        }

        res.json({
          message: `${updatedUser.name} has been rehired successfully`,
          user: updatedUser,
        });
      } catch (error) {
        console.error('Rehire user error:', error);
        res.status(500).json({ message: 'Server error' });
      }
    });
    // PATCH route for updating role
    app.patch('/users/:id/role', async (req, res) => {
      const id = req.params.id;
      const { role } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid ID' });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role } }
        );

        if (result.modifiedCount > 0) {
          res.status(200).json({ message: 'Role updated successfully' });
        } else {
          res.status(404).json({ message: 'User not found or role unchanged' });
        }
      } catch (err) {
        console.error('Error updating role:', err);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    // Update user profile by email.........................
 app.put('/user/:email', async (req, res) => {
  const emailParam = req.params.email;
  const { name, photo } = req.body;

  const result = await usersCollection.findOneAndUpdate(
    { email: { $regex: `^${emailParam}$`, $options: 'i' } },
    { $set: { name, photo } },
    { returnDocument: 'after' }
  );
  res.json({ user: result.value });
});

    app.get('/users/:email/role', async (req, res) => {
      try {
        const emailParam = req.params.email;

        // Case-insensitive regex query
        const user = await usersCollection.findOne({
          email: { $regex: `^${emailParam}$`, $options: 'i' } // i = ignore case
        });

        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ role: user.role || 'employee' });
      } catch (error) {
        console.error('Error fetching user role:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });


    app.get('/user/:email', async (req, res) => {
      try {
        const emailParam = req.params.email;


        const user = await usersCollection.findOne({
          email: { $regex: `^${emailParam}$`, $options: 'i' }
        });

        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }


        res.status(200).json(user);
      } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });




    // payroll APIs ...

    app.post('/payroll', async (req, res) => {
      try {
        const exists = await payrollCollection.findOne({
          userId: req.body.userId,
          month: req.body.month,
          year: req.body.year,
        });
        if (exists) {
          return res.status(409).json({ message: 'Already requested for this month.' });
        }

        const result = await payrollCollection.insertOne({
          ...req.body,
          status: 'pending'
        });

        res.status(201).json({ insertedId: result.insertedId });
      } catch (error) {
        console.error('Error in /payroll POST:', error);
        res.status(500).json({ message: 'Failed to create payroll entry' });
      }
    });

    app.post('/create-payment-intent', async (req, res) => {
      const { amount, name, email } = req.body;

      // try {
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount * 100, // smallest currency unit
        currency: 'BDT',      // Capitalized currency code
        metadata: { name, email },
      });

      res.send({ clientSecret: paymentIntent.client_secret });
      // } catch (error) {
      //   res.status(500).send({ error: error.message });
      // }
    });

    // Example: POST /payroll/payment-success
    app.post('/payroll/payment-success', async (req, res) => {
      const { payrollId, transactionId } = req.body;

      const result = await payrollCollection.updateOne(
        { _id: new ObjectId(payrollId) },
        {
          $set: {
            paid: true,
            transactionId,
            paymentDate: new Date(),
            status: 'paid',
          },
        }
      );

      res.send(result);
    });


    app.get('/payroll', verifyFBToken, async (req, res) => {
      const userId = req.query.userId;
      if (!userId) return res.status(400).json({ message: "User ID required" });

      try {
        const payments = await payrollCollection.find({ userId }).toArray();
        res.status(200).json(payments);
      } catch (error) {
        console.error("Error fetching payrolls:", error);
        res.status(500).json({ message: "Failed to fetch payroll data" });
      }
    });



    app.get('/payroll/by-email', verifyFBToken, async (req, res) => {
      try {
        const email = req.query.email;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 5;

        if (!email) {
          return res.status(400).json({ message: "Email query parameter is required" });
        }

        const filter = { email: email.toLowerCase() };

        const totalCount = await payrollCollection.countDocuments(filter);

        const payrolls = await payrollCollection
          .find(filter)
          .skip((page - 1) * limit)
          .limit(limit)
          .toArray();

        res.json({
          data: payrolls,
          totalCount,
        });
      } catch (error) {
        console.error("Error fetching payroll by email:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });


    app.get('/payroll/all', verifyFBToken, async (req, res) => {
      try {
        const payrolls = await payrollCollection.find().toArray();
        res.send(payrolls);
      } catch (error) {
        console.error("Failed to load payrolls:", error);
        res.status(500).send({ error: 'Failed to load payrolls' });
      }
    });

    app.get('/payroll/:id', async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid payroll ID' });
      }

      try {
        const payment = await payrollCollection.findOne({ _id: new ObjectId(id) });
        if (!payment) {
          return res.status(404).json({ message: 'Payment not found' });
        }
        res.json(payment);
      } catch (error) {
        console.error('Error fetching payroll:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });



    // Pay salary for a payroll entry
    app.patch('/payroll/pay/:id', verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const { transactionId } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ error: "Invalid ID format" });
      }

      if (!transactionId) {
        return res.status(400).send({ error: "Missing transaction ID" });
      }

      const filter = { _id: new ObjectId(id), paid: false };
      const updateDoc = {
        $set: {
          paid: true,
          paymentDate: new Date(),
          status: 'paid',
          transactionId: transactionId  // ✅ Transaction ID saved here
        }
      };

      try {
        const result = await payrollCollection.updateOne(filter, updateDoc);

        if (result.modifiedCount === 0) {
          return res.status(404).send({ message: "Already paid or not found" });
        }

        const updated = await payrollCollection.findOne({ _id: new ObjectId(id) });
        res.send(updated);
      } catch (error) {
        console.error("❌ Failed to update payment:", error);
        res.status(500).send({ error: 'Failed to update payment' });
      }
    });


    // Reviwe Setion 
    // --- Reviews APIs ---

    // GET all reviews
    app.get('/reviews', async (req, res) => {
      try {
        const reviews = await ReviewCollection.find().sort({ _id: -1 }).toArray();
        res.json(reviews);
      } catch (err) {
        console.error('Error fetching reviews:', err);
        res.status(500).json({ error: 'Server error' });
      }
    });

    // POST a new review
    app.post('/reviews', async (req, res) => {
      try {
        const { title, content, rating, name } = req.body;

        if (!title || !content) {
          return res.status(400).json({ error: 'Title and content required' });
        }

        const newReview = {
          title,
          content,
          rating: rating || 5,
          name: name || 'Anonymous',
          date: new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
        };

        const result = await ReviewCollection.insertOne(newReview);
        res.status(201).json({ _id: result.insertedId, ...newReview });
      } catch (err) {
        console.error('Error adding review:', err);
        res.status(500).json({ error: 'Failed to add review' });
      }
    });

    // DELETE a review by ID
    app.delete('/reviews/:id', async (req, res) => {
      try {
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ error: 'Invalid review ID' });
        }

        const result = await ReviewCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
          return res.status(404).json({ error: 'Review not found' });
        }

        res.json({ message: 'Review deleted' });
      } catch (err) {
        console.error('Error deleting review:', err);
        res.status(500).json({ error: 'Failed to delete review' });
      }
    });



    // MongoDB connection ping
    // await client.db("admin").command({ ping: 1 });
    // console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // don't close client here
  }
}
run().catch(console.dir);

// Home route
app.get('/', (req, res) => {
  res.send('Workfeeld Server is on!');
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
